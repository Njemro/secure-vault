package unibl.sni.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Request to create a secret. The owner id is NOT part of the request:
 * future controllers must take it from the authenticated security context.
 *
 * <p>Binary fields are raw {@code byte[]}; at the JSON API boundary they are
 * expected as standard Base64 strings (Jackson's default byte[] handling) -
 * no custom encoding framework. Do not log instances of this record: it
 * carries encrypted payloads and IVs.
 *
 * <p>Size limits mirror the schema columns.
 */
public record SecretCreateRequest(
        @NotBlank @Size(max = 255) String name,
        @Size(max = 1000) String description,
        @NotNull @Size(min = 1, max = 50000) byte[] encryptedValue,
        @NotNull @Size(min = 1, max = 1024) byte[] encryptedDek,
        @NotNull @Size(min = 1, max = 128) byte[] contentIv,
        @NotNull @Size(min = 1, max = 128) byte[] dekIv,
        @NotBlank @Size(max = 50) String encryptionAlgorithm) {
}
