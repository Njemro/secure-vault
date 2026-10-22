package unibl.sni.securevault.dto;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Response carrying a user's key material. Returned only to the authenticated
 * owner via {@code GET /api/users/me/keys}. The public key may also be
 * retrieved for any user via {@code GET /api/users/{id}/public-key}, which
 * deliberately excludes encrypted private-key material.
 * <p>All cryptographic values are raw {@code byte[]}; serialized as standard
 * Base64 at the JSON API boundary.
 */
public record UserKeyResponse(

        UUID userId,

        byte[] publicKey,

        byte[] encryptedPrivateKey,

        byte[] privateKeyIv,

        String kdfAlgorithm,

        String kdfParameters,

        LocalDateTime createdAt
) {
}