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
import unibl.sni.securevault.service.MfaChallengeService;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Service
public class AuthService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final UserRepository userRepository;
    private final MfaService mfaService;
    private final MfaChallengeService mfaChallengeService;
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
            MfaChallengeService mfaChallengeService,
            AuditLogService auditLogService) {
        this.keycloakServerUrl = keycloakServerUrl;
        this.keycloakRealm = keycloakRealm;
        this.keycloakClientId = keycloakClientId;
        this.userRepository = userRepository;
        this.mfaService = mfaService;
        this.mfaChallengeService = mfaChallengeService;
        this.auditLogService = auditLogService;
    private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}

    public LoginResponse login(String username, String password, String sourceIp) {
        if (keycloakServerUrl == null || keycloakServerUrl.isBlank()) {
            throw new InvalidOperationRequestException("Authentication is not configured");
        private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
        String keycloakToken = null;
        try {
            keycloakToken = obtainKeycloakToken(username, password);
        } catch (InvalidOperationRequestException e) {
            if (e.getMessage().contains("mfa_required") || e.getMessage().contains("interaction_required")) {
                var user = userRepository.findByUsername(username)
                        .orElseThrow(() -> new InvalidOperationRequestException("User is not provisioned in Secure Vault"));
                if (user.getStatus() != UserStatus.ACTIVE) {
                    auditLogService.record(user, "LOGIN_FAILED", "AUTH",
                            user.getId().toString(), "{\"reason\":\"account_not_active\",\"status\":\"" + user.getStatus() + "\"}");
                    throw new InvalidOperationRequestException("Account is not active");
                private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
                boolean mfaEnrolled = mfaService.isMfaEnabled(user.getId());
                if (mfaEnrolled) {
                    UUID challengeId = mfaChallengeService.createChallenge(user.getId());
                    auditLogService.record(user, "LOGIN_MFA_REQUIRED", "AUTH",
                            user.getId().toString(), "{\"challengeId\":\"" + challengeId + "\"}");
                    return buildMfaRequiredResponse(user, challengeId);
                private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
                auditLogService.record(user, "LOGIN_SUCCESS", "AUTH",
                        user.getId().toString(), "{\"mfaRequired\":false}");
                return new LoginResponse(
                        keycloakToken, "Bearer", 300,
                        user.getId(), user.getUsername(), user.getRole(), user.getStatus(),
                        false, true, null, LocalDateTime.now()
                );
            private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
            throw new InvalidOperationRequestException("Invalid username or password");
        } catch (Exception e) {
            auditLogService.record(null, "LOGIN_FAILED", "AUTH",
                    null, "{\"username\":\"" + username + "\",\"reason\":\"invalid_credentials\"}");
            throw new InvalidOperationRequestException("Invalid username or password");
        private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
        String keycloakId = extractSubject(keycloakToken);
        var user = userRepository.findByKeycloakId(keycloakId)
                .orElseThrow(() -> new InvalidOperationRequestException("User is not provisioned in Secure Vault"));
        if (user.getStatus() != UserStatus.ACTIVE) {
            auditLogService.record(user, "LOGIN_FAILED", "AUTH",
                    user.getId().toString(), "{\"reason\":\"account_not_active\",\"status\":\"" + user.getStatus() + "\"}");
            throw new InvalidOperationRequestException("Account is not active");
        private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
        boolean mfaEnrolled = mfaService.isMfaEnabled(user.getId());
        if (mfaEnrolled) {
            UUID challengeId = mfaChallengeService.createChallenge(user.getId());
            auditLogService.record(user, "LOGIN_MFA_REQUIRED", "AUTH",
                    user.getId().toString(), "{\"challengeId\":\"" + challengeId + "\"}");
            return buildMfaRequiredResponse(user, challengeId);
        private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
        auditLogService.record(user, "LOGIN_SUCCESS", "AUTH",
                user.getId().toString(), "{\"mfaRequired\":false}");
        return new LoginResponse(
                keycloakToken, "Bearer", 300,
                user.getId(), user.getUsername(), user.getRole(), user.getStatus(),
                false, true, null, LocalDateTime.now()
        );
    private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}

    public LoginResponse verifyMfa(String challengeId, String code, String sourceIp) {
        if (challengeId == null || challengeId.isBlank()) {
            throw new InvalidOperationRequestException("MFA challenge is required");
        private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
        if (code == null || code.isBlank()) {
            throw new InvalidOperationRequestException("Verification code is required");
        private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
        UUID challengeUuid;
        try {
            challengeUuid = UUID.fromString(challengeId);
        } catch (IllegalArgumentException e) {
            throw new InvalidOperationRequestException("Invalid MFA challenge format");
        private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
        UUID userId = mfaChallengeService.consumeChallenge(challengeUuid);
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new InvalidOperationRequestException("Invalid session"));
        if (!mfaService.verifyLoginCode(userId, code)) {
            auditLogService.record(user, "MFA_VERIFY_FAILED", "AUTH",
                    user.getId().toString(), "{\"reason\":\"invalid_code\"}");
            throw new InvalidOperationRequestException("Invalid verification code");
        private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
        String accessToken = issueSessionToken(user);
        auditLogService.record(user, "LOGIN_MFA_SUCCESS", "AUTH",
                user.getId().toString(), "{\"mfaCompleted\":true}");
        return new LoginResponse(
                accessToken, "Bearer", 300,
                user.getId(), user.getUsername(), user.getRole(), user.getStatus(),
                false, true, null, LocalDateTime.now()
        );
    private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}

    private String extractSubject(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new InvalidOperationRequestException("Invalid token format");
        private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), java.nio.charset.StandardCharsets.UTF_8);
        int subIdx = payload.indexOf("\"sub\"");
        if (subIdx < 0) {
            throw new InvalidOperationRequestException("Token missing subject claim");
        private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
        int colonIdx = payload.indexOf(':', subIdx);
        int start = payload.indexOf('"', colonIdx + 1) + 1;
        int end = payload.indexOf('"', start);
        return payload.substring(start, end);
    private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}

    private LoginResponse buildMfaRequiredResponse(unibl.sni.securevault.entity.User user, UUID challengeId) {
        return new LoginResponse(
                null, "Bearer", 0,
                user.getId(), user.getUsername(), user.getRole(), user.getStatus(),
                true, true, challengeId, LocalDateTime.now()
        );
    private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
    private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}
private String obtainKeycloakToken(String username, String password) {
        String tokenUri = keycloakServerUrl + "/realms/" + keycloakRealm
                + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", keycloakClientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if (response.getStatusCode().isError() || response.getBody() == null) {
            Map<String, String> errorBody = response.getBody();
            String error = errorBody != null ? errorBody.get("error") : null;
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
}

