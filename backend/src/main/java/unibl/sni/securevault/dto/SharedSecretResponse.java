package unibl.sni.securevault.dto;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * A secret shared with the authenticated recipient: ciphertext and IVs from
 * {@link unibl.sni.securevault.entity.Secret}, plus the DEK wrapped for this
 * recipient from {@link unibl.sni.securevault.entity.SecretShare}. All
 * cryptographic values are opaque bytes produced client-side; the backend
 * never decrypts or unwraps them (AGENTS.md section 4).
 */
public record SharedSecretResponse(
        UUID id,
        UUID ownerId,
        String name,
        String description,
        byte[] encryptedValue,
        byte[] contentIv,
        String encryptionAlgorithm,
        LocalDateTime createdAt,
        UUID shareId,
        byte[] recipientEncryptedDek) {
}