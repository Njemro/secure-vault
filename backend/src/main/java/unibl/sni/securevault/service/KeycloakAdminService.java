package unibl.sni.securevault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/**
 * Client for the Keycloak Admin REST API, used during registration to create
 * the user's Keycloak account.
 * <p>Authentication with Keycloak's admin endpoints uses the {@code admin-cli}
 * client and the bootstrap administrator credentials (direct grant). The
 * admin access token is obtained per request and is short-lived.
 * <p>No vault key material, master password or plaintext secret ever passes
 * through this service - it only manages Keycloak account identity.
 */
@Service
public class KeycloakAdminService {

    private final RestTemplate restTemplate = new RestTemplate();

    private final String serverUrl;
    private final String realm;
    private final String adminUsername;
    private final String adminPassword;
    private final String adminClientId;

    public KeycloakAdminService(
            @Value("${keycloak.server.url:}") String serverUrl,
            @Value("${keycloak.realm:}") String realm,
            @Value("${keycloak.admin.username:}") String adminUsername,
            @Value("${keycloak.admin.password:}") String adminPassword,
            @Value("${keycloak.admin.client-id:admin-cli}") String adminClientId) {
        this.serverUrl = serverUrl;
        this.realm = realm;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.adminClientId = adminClientId;
    }

    /**
     * Returns whether Keycloak admin integration is configured.
     */
    public boolean isConfigured() {
        return serverUrl != null && !serverUrl.isBlank()
                && realm != null && !realm.isBlank()
                && adminUsername != null && !adminUsername.isBlank()
                && adminPassword != null && !adminPassword.isBlank();
    }

    /**
     * Obtains an admin access token from Keycloak via the direct grant API.
     */
    private String obtainAdminToken() {
        String tokenUri = serverUrl + "/realms/master/protocol/openid-connect/token";

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", adminClientId);
        form.add("username", adminUsername);
        form.add("password", adminPassword);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);
        Object token = response.getBody() == null ? null : response.getBody().get("access_token");
        if (token == null) {
            throw new IllegalStateException("Keycloak admin token response did not contain an access token");
        }
        return token.toString();
    }

    /**
     * Creates a user in the Keycloak realm with the given username, email and
     * password. Returns the Keycloak-assigned user id (extracted from the
     * {@code Location} header of the creation response).
     * <p>The user is created with {@code enabled = true} and
     * {@code emailVerified = false}.
     */
    public String createUser(String username, String email, String password) {
        if (!isConfigured()) {
            throw new IllegalStateException("Keycloak admin integration is not configured");
        }

        String adminToken = obtainAdminToken();
        String createUri = serverUrl + "/admin/realms/" + realm + "/users";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(userRepresentation(username, email, password), headers);

        ResponseEntity<Void> response = restTemplate.postForEntity(createUri, request, Void.class);
        String location = response.getHeaders().getLocation() != null
                ? response.getHeaders().getLocation().toString()
                : null;
        if (location == null) {
            throw new IllegalStateException("Keycloak user creation response did not contain a Location header");
        }
        return location.substring(location.lastIndexOf('/') + 1);
    }

    /**
     * Deletes the Keycloak user with the given id. Used to roll back a
     * partially completed registration (Keycloak user created but local
     * provisioning failed). Best-effort: failures are swallowed so the
     * original error is not masked.
     */
    public void deleteUser(String keycloakId) {
        if (!isConfigured() || keycloakId == null || keycloakId.isBlank()) {
            return;
        }
        try {
            String adminToken = obtainAdminToken();
            String deleteUri = serverUrl + "/admin/realms/" + realm + "/users/" + keycloakId;

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            HttpEntity<Void> request = new HttpEntity<>(headers);

            restTemplate.exchange(deleteUri, org.springframework.http.HttpMethod.DELETE, request, Void.class);
        } catch (RestClientException e) {
            // Best-effort rollback: swallow so the original failure is surfaced.
        }
    }

    private static Map<String, Object> userRepresentation(String username, String email, String password) {
        java.util.Map<String, Object> user = new java.util.LinkedHashMap<>();
        user.put("username", username);
        user.put("email", email);
        user.put("enabled", true);
        user.put("emailVerified", false);
        user.put("credentials", java.util.List.of(
                java.util.Map.of(
                        "type", "password",
                        "value", password,
                        "temporary", false
                )
        ));
        return user;
    }
}
