package unibl.sni.securevault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import unibl.sni.securevault.entity.Role;

import java.util.*;

@Service
public class KeycloakAdminService {
    private final RestTemplate restTemplate = new RestTemplate();
    private final String serverUrl;
    private final String realm;
    private final String clientId;
    private final String clientSecret;

    public KeycloakAdminService(
            @Value("${keycloak.server-url:}") String serverUrl,
            @Value("${keycloak.realm:secure-vault}") String realm,
            @Value("${keycloak.admin.client-id:secure-vault-admin}") String clientId,
            @Value("${keycloak.admin.client-secret:}") String clientSecret) {
        this.serverUrl = trimSlash(serverUrl);
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public boolean isConfigured() {
        return serverUrl != null && !serverUrl.isBlank()
                && realm != null && !realm.isBlank()
                && clientId != null && !clientId.isBlank()
                && clientSecret != null && !clientSecret.isBlank();
    }

    private static String trimSlash(String value) {
        if (value == null) return "";
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private String obtainAdminToken() {
        if (!isConfigured()) {
            throw new IllegalStateException("Keycloak service-account integration is not configured");
        }
        String tokenUri = serverUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        ResponseEntity<Map> response = restTemplate.postForEntity(
                tokenUri, new HttpEntity<>(form, headers), Map.class);
        Object token = response.getBody() == null ? null : response.getBody().get("access_token");
        if (token == null) throw new IllegalStateException("Keycloak did not return an admin access token");
        return token.toString();
    }

    private HttpHeaders adminHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(obtainAdminToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    public String createUser(String username, String email, String password) {
        String uri = serverUrl + "/admin/realms/" + realm + "/users";
        ResponseEntity<Void> response = restTemplate.postForEntity(
                uri, new HttpEntity<>(userRepresentation(username, email, password), adminHeaders()), Void.class);
        String location = response.getHeaders().getLocation() == null ? null
                : response.getHeaders().getLocation().toString();
        if (location == null) throw new IllegalStateException("Keycloak user creation returned no Location header");
        return location.substring(location.lastIndexOf('/') + 1);
    }

    /** Replaces only the two optional application realm roles. DEVELOPER is represented by neither role. */
    public Role replaceApplicationRole(String keycloakId, Role requestedRole) {
        Role previous = getApplicationRole(keycloakId);
        String base = userUri(keycloakId) + "/role-mappings/realm";

        // Resolve the destination role before removing any existing mapping.
        Map<String, Object> requestedRepresentation = null;
        if (requestedRole == Role.ADMIN || requestedRole == Role.TEAM_LEAD) {
            ResponseEntity<Map> roleResponse = restTemplate.exchange(
                    serverUrl + "/admin/realms/" + realm + "/roles/" + requestedRole.name(),
                    HttpMethod.GET, new HttpEntity<>(adminHeaders()), Map.class);
            requestedRepresentation = roleResponse.getBody();
            if (requestedRepresentation == null) {
                throw new IllegalStateException("Keycloak realm role not found: " + requestedRole);
            }
        }

        List<Map<String, Object>> mappings = restTemplate.exchange(
                base, HttpMethod.GET, new HttpEntity<>(adminHeaders()), List.class).getBody();
        List<Map<String, Object>> remove = new ArrayList<>();
        if (mappings != null) {
            for (Map<String, Object> mapping : mappings) {
                String name = String.valueOf(mapping.get("name"));
                if ("ADMIN".equals(name) || "TEAM_LEAD".equals(name)) remove.add(mapping);
            }
        }
        if (!remove.isEmpty()) {
            restTemplate.exchange(base, HttpMethod.DELETE,
                    new HttpEntity<>(remove, adminHeaders()), Void.class);
        }

        if (requestedRepresentation != null) {
            try {
                restTemplate.exchange(base, HttpMethod.POST,
                        new HttpEntity<>(List.of(requestedRepresentation), adminHeaders()), Void.class);
            } catch (RuntimeException error) {
                try {
                    // Restore the previous mapping if Keycloak rejected the new assignment.
                    if (previous == Role.ADMIN || previous == Role.TEAM_LEAD) {
                        ResponseEntity<Map> oldRole = restTemplate.exchange(
                                serverUrl + "/admin/realms/" + realm + "/roles/" + previous.name(),
                                HttpMethod.GET, new HttpEntity<>(adminHeaders()), Map.class);
                        if (oldRole.getBody() != null) {
                            restTemplate.exchange(base, HttpMethod.POST,
                                    new HttpEntity<>(List.of(oldRole.getBody()), adminHeaders()), Void.class);
                        }
                    }
                } catch (RuntimeException rollbackError) {
                    error.addSuppressed(rollbackError);
                }
                throw error;
            }
        }
        return previous;
    }

    public Role getApplicationRole(String keycloakId) {
        String uri = userUri(keycloakId) + "/role-mappings/realm";
        List<Map<String, Object>> mappings = restTemplate.exchange(
                uri, HttpMethod.GET, new HttpEntity<>(adminHeaders()), List.class).getBody();
        if (mappings != null) {
            for (Map<String, Object> mapping : mappings) {
                if ("ADMIN".equals(mapping.get("name"))) return Role.ADMIN;
                if ("TEAM_LEAD".equals(mapping.get("name"))) return Role.TEAM_LEAD;
            }
        }
        return Role.DEVELOPER;
    }

    public void setUserEnabled(String keycloakId, boolean enabled) {
        String uri = userUri(keycloakId);
        ResponseEntity<UserRepresentation> response = restTemplate.exchange(
                uri, HttpMethod.GET, new HttpEntity<>(adminHeaders()), UserRepresentation.class);
        UserRepresentation user = response.getBody();
        if (user == null) throw new IllegalStateException("Keycloak user not found");
        user.setEnabled(enabled);
        restTemplate.exchange(uri, HttpMethod.PUT,
                new HttpEntity<>(user, adminHeaders()), Void.class);
    }

    public void logoutUser(String keycloakId) {
        restTemplate.exchange(userUri(keycloakId) + "/logout",
                HttpMethod.POST, new HttpEntity<>(adminHeaders()), Void.class);
    }

    public void deleteUser(String keycloakId) {
        if (!isConfigured() || keycloakId == null || keycloakId.isBlank()) return;
        try {
            restTemplate.exchange(userUri(keycloakId), HttpMethod.DELETE,
                    new HttpEntity<>(adminHeaders()), Void.class);
        } catch (RestClientException ignored) {
            // Best-effort rollback during failed registration.
        }
    }

    private String userUri(String keycloakId) {
        return serverUrl + "/admin/realms/" + realm + "/users/" + keycloakId;
    }

    private UserRepresentation userRepresentation(String username, String email, String password) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(email);
        user.setEnabled(true);
        user.setEmailVerified(false);
        user.setRequiredActions(List.of("CONFIGURE_TOTP"));
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);
        user.setCredentials(List.of(credential));
        return user;
    }
}
