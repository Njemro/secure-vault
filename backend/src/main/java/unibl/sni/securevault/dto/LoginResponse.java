package unibl.sni.securevault.dto;

import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.UserStatus;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Response to a successful login. Carries the access token plus non-sensitive
 * user metadata. No TOTP secrets, recovery codes, or raw Keycloak tokens are
 * included.
 */
public record LoginResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        UUID userId,
        String username,
        Role role,
        UserStatus status,
        boolean mfaRequired,
        boolean mfaEnrolled,
        LocalDateTime issuedAt
) {
}