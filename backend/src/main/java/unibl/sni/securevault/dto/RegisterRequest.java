package unibl.sni.securevault.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request to register a new Secure Vault account.
 * <p>The {@code keycloakPassword} is the user's Keycloak (authentication)
 * password - it is sent to the backend so the backend can create the user in
 * Keycloak. The vault master password is NOT part of this request: it is
 * established client-side and never sent to the backend (AGENTS.md section 8).
 */
public record RegisterRequest(

        @NotBlank
        @Size(min = 3, max = 100)
        String username,

        @NotBlank
        @Email
        @Size(max = 255)
        String email,

        @NotBlank
        @Size(min = 8, max = 128)
        String keycloakPassword
) {
}