package unibl.sni.securevault.dto;

import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.UserStatus;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * User profile response. Contains no credentials: passwords and TOTP live in
 * Keycloak, the vault master password never leaves the browser, and the
 * internal keycloakId linkage is not exposed.
 */
public record UserProfileResponse(
        UUID id,
        String username,
        Role role,
        UserStatus status,
        LocalDateTime createdAt) {
}
