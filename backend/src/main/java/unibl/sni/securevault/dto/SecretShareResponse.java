package unibl.sni.securevault.dto;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One share of one secret with one recipient. {@code encryptedDek} is the DEK
 * wrapped for that recipient (RSA-OAEP) and is only shown to the secret owner
 * or the recipient; it is ciphertext. Expected as Base64 at the JSON
 * API boundary. Do not log instances.
 */
public record SecretShareResponse(
        UUID id,
        UUID secretId,
        UUID recipientId,
        byte[] encryptedDek,
        LocalDateTime createdAt) {
}
