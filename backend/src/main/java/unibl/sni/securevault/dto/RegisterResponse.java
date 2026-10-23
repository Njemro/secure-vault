package unibl.sni.securevault.dto;

/**
 * Response to a successful registration.
 * <p>Carries only non-sensitive identifiers: the Keycloak user id and the
 * local username. No tokens, passwords or key material are included.
 */
public record RegisterResponse(

        String keycloakId,

        String username,

        String message
) {
}