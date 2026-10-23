package unibl.sni.securevault.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request to authenticate a user. The Keycloak password (authentication
 * password) is validated against Keycloak; the vault master password is never
 * part of this request (AGENTS.md section 8).
 */
public record LoginRequest(
        @NotBlank String username,
        @NotBlank String password
) {
}