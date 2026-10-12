package unibl.sni.securevault.dto;

import java.util.UUID;

/**
 * Public key of a user, for sharing: the minimum the client needs to wrap a
 * DEK (recipient id, display username, public key). The encrypted private
 * key is NEVER included in this or any other ordinary response.
 *
 * <p>{@code publicKey} is the raw key encoding (e.g. X.509 SubjectPublicKeyInfo
 * DER bytes); expected as standard Base64 at the JSON API boundary.
 */
public record PublicKeyResponse(
        UUID userId,
        String username,
        byte[] publicKey) {
}
