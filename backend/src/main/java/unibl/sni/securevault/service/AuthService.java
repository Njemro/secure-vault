package unibl.sni.securevault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import unibl.sni.securevault.dto.LoginResponse;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Service
public class AuthService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final UserRepository userRepository;
    private final MfaService mfaService;
    private final AuditLogService auditLogService;

    private final String keycloakServerUrl;
    private final String keycloakRealm;
    private final String keycloakClientId;

    public AuthService(
            @Value("${keycloak.server.url:}") String keycloakServerUrl,
            @Value("${keycloak.realm:secure-vault}") String keycloakRealm,
            @Value("${keycloak.client-id:admin-cli}") String keycloakClientId,
            UserRepository userRepository,
            MfaService mfaService,
            AuditLogService auditLogService) {
        this.keycloakServerUrl = keycloakServerUrl;
        this.keycloakRealm = keycloakRealm;
        this.keycloakClientId = keycloakClientId;
        this.userRepository = userRepository;
        this.mfaService = mfaService;
        this.auditLogService = auditLogService;
    }

    public LoginResponse login(String username, String password, String sourceIp) {
        if (keycloakServerUrl == null || keycloakServerUrl.isBlank()) {
            throw new InvalidOperationRequestException("Authentication is not configured");
        }
        String keycloakToken = null;
        try {
            keycloakToken = obtainKeycloakToken(username, password);
        } catch (InvalidOperationRequestException e) {
            // Keycloak may return "mfa_required" or "interaction_required" when MFA is enrolled.
            // Instead of failing login, authenticate the user locally and return MFA required
            // response so the client can complete TOTP verification.
            if (e.getMessage().contains("mfa_required") || e.getMessage().contains("interaction_required")) {
                // Look up the user by username to build the MFA-required response
                var user = userRepository.findByUsername(username)
                        .orElseThrow(() -> new InvalidOperationRequestException("User is not provisioned in Secure Vault"));
                if (user.getStatus() != UserStatus.ACTIVE) {
                    auditLogService.record(user, "LOGIN_FAILED", "AUTH",
                            user.getId().toString(), "{\"reason\":\"account_not_active\",\"status\":\"" + user.getStatus() + "\"}");
                    throw new InvalidOperationRequestException("Account is not active");
                }
                boolean mfaEnrolled = mfaService.isMfaEnabled(user.getId());
                if (mfaEnrolled) {
                    auditLogService.record(user, "LOGIN_MFA_REQUIRED", "AUTH",
                            user.getId().toString(), "{\"mfaRequired\":true}");
                    return buildMfaRequiredResponse(user);
                } else {
                    // User exists but MFA not enrolled - this shouldn't happen if Keycloak returned mfa_required,
                    // but handle gracefully
                    auditLogService.record(user, "LOGIN_SUCCESS", "AUTH",
                            user.getId().toString(), "{\"mfaRequired\":false}");
                    return new LoginResponse(
                            keycloakToken, "Bearer", 300,
                            user.getId(), user.getUsername(), user.getRole(), user.getStatus(),
                            false, true, LocalDateTime.now()
                    );
                }
            }
            throw new InvalidOperationRequestException("Invalid username or password");
        } catch (Exception e) {
            auditLogService.record(null, "LOGIN_FAILED", "AUTH",
                    null, "{\"username\":\"" + username + "\",\"reason\":\"invalid_credentials\"}");
            throw new InvalidOperationRequestException("Invalid username or password");
        }
        String keycloakId = extractSubject(keycloakToken);
        var user = userRepository.findByKeycloakId(keycloakId)
                .orElseThrow(() -> new InvalidOperationRequestException("User is not provisioned in Secure Vault"));
        if (user.getStatus() != UserStatus.ACTIVE) {
            auditLogService.record(user, "LOGIN_FAILED", "AUTH",
                    user.getId().toString(), "{\"reason\":\"account_not_active\",\"status\":\"" + user.getStatus() + "\"}");
            throw new InvalidOperationRequestException("Account is not active");
        }
        boolean mfaEnrolled = mfaService.isMfaEnabled(user.getId());
        if (mfaEnrolled) {
            auditLogService.record(user, "LOGIN_MFA_REQUIRED", "AUTH",
                    user.getId().toString(), "{\"mfaRequired\":true}");
            return buildMfaRequiredResponse(user);
        }
        auditLogService.record(user, "LOGIN_SUCCESS", "AUTH",
                user.getId().toString(), "{\"mfaRequired\":false}");
        return new LoginResponse(
                keycloakToken, "Bearer", 300,
                user.getId(), user.getUsername(), user.getRole(), user.getStatus(),
                false, true, LocalDateTime.now()
        );
    }

    public LoginResponse verifyMfa(String tempToken, String code, String sourceIp) {
        if (tempToken == null || tempToken.isBlank()) {
            throw new InvalidOperationRequestException("Temporary token is required");
        }
        if (code == null || code.isBlank()) {
            throw new InvalidOperationRequestException("Verification code is required");
        }
        UUID userId = extractUserIdFromTempToken(tempToken);
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new InvalidOperationRequestException("Invalid session"));
        if (!mfaService.verifyLoginCode(userId, code)) {
            auditLogService.record(user, "MFA_VERIFY_FAILED", "AUTH",
                    user.getId().toString(), "{\"reason\":\"invalid_code\"}");
            throw new InvalidOperationRequestException("Invalid verification code");
        }
        String accessToken = issueSessionToken(user);
        auditLogService.record(user, "LOGIN_MFA_SUCCESS", "AUTH",
                user.getId().toString(), "{\"mfaCompleted\":true}");
        return new LoginResponse(
                accessToken, "Bearer", 300,
                user.getId(), user.getUsername(), user.getRole(), user.getStatus(),
                false, true, LocalDateTime.now()
        );
    }

    public LoginResponse me(String keycloakId) {
        var user = userRepository.findByKeycloakId(keycloakId)
                .orElseThrow(() -> new InvalidOperationRequestException("User not found"));
        return new LoginResponse(
                null, "Bearer", 0,
                user.getId(), user.getUsername(), user.getRole(), user.getStatus(),
                user.isMfaEnabled(), user.isMfaEnabled(), LocalDateTime.now()
        );
    }

    private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/token";
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
            // Keycloak may return "mfa_required" or "interaction_required" when MFA is enrolled
            if (error != null && (error.contains("mfa_required") || error.contains("interaction_required"))) {
                throw new InvalidOperationRequestException("mfa_required:" + error);
            }
            throw new InvalidOperationRequestException("Invalid username or password");
        }
        Object token = response.getBody().get("access_token");
        if (token == null) {
            throw new InvalidOperationRequestException("Invalid username or password");
        }
        return token.toString();
    }

    private String extractSubject(String jwt) {
        String[] parts = jwt.split("\\");
        if (parts.length != 3) {
            throw new InvalidOperationRequestException("Invalid token format");
        }
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), java.nio.charset.StandardCharsets.UTF_8);
        int subIdx = payload.indexOf("\"sub\"");
        if (subIdx < 0) {
            throw new InvalidOperationRequestException("Token missing subject claim");
        }
        int colonIdx = payload.indexOf(':', subIdx);
        int start = payload.indexOf('"', colonIdx + 1) + 1;
        int end = payload.indexOf('"', start);
        return payload.substring(start, end);
    }

    private LoginResponse buildMfaRequiredResponse(unibl.sni.securevault.entity.User user) {
        return new LoginResponse(
                null, "Bearer", 0,
                user.getId(), user.getUsername(), user.getRole(), user.getStatus(),
                true, true, LocalDateTime.now()
        );
    }

    private String issueSessionToken(unibl.sni.securevault.entity.User user) {
        java.util.Base64.Encoder encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String payload = encoder.encodeToString((
                "{\"sub\":\"" + user.getKeycloakId() + "\",\"userId\":\"" + user.getId() +
                        "\",\"username\":\"" + user.getUsername() + "\",\"role\":\"" + user.getRole() +
                        "\",\"mfa\":\"true\",\"iss\":\"secure-vault-backend\"}"
        ).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return header + "." + payload + ".sig";
    }

    private UUID extractUserIdFromTempToken(String tempToken) {
        String[] parts = tempToken.split("\\");
        if (parts.length < 2) {
            throw new InvalidOperationRequestException("Invalid session token");
        }
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), java.nio.charset.StandardCharsets.UTF_8);
        int idx = payload.indexOf("\"userId\"");
        if (idx < 0) {
            throw new InvalidOperationRequestException("Invalid session token");
        }
        int start = payload.indexOf('"', payload.indexOf(':', idx) + 1) + 1;
        int end = payload.indexOf('"', start);
        return UUID.fromString(payload.substring(start, end));
    }
}
