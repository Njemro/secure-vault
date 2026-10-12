package unibl.sni.securevault.dto;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * A secret with its ciphertext and cryptographic metadata only - there is no
 * plaintext secret field in this DTO by design (zero-knowledge architecture,
 * AGENTS.md section 1). Binary fields are raw {@code byte[]}; expected as
 * standard Base64 at the JSON API boundary. Do not log instances.
 */
public record SecretResponse(
        UUID id,
        UUID ownerId,
        String name,
        String description,
        byte[] encryptedValue,
        byte[] encryptedDek,
        byte[] contentIv,
        byte[] dekIv,
        String encryptionAlgorithm,
        LocalDateTime createdAt,
        LocalDateTime lastRotatedAt) {
}
