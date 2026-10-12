package unibl.sni.securevault.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

/**
 * One recipient entry of a share request: recipient id paired with the
 * recipient-encrypted DEK. Binary data is raw {@code byte[]}; expected as
 * Base64 at the JSON API boundary. Do not log instances of this record.
 */
public record RecipientShareInput(
        @NotNull UUID recipientId,
        @NotNull @Size(min = 1, max = 1024) byte[] encryptedDek) {
}
