package unibl.sni.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Request to register or update the authenticated user's key material.
 * All cryptographic values are raw {@code byte[]}; expected as standard
 * Base64 at the JSON API boundary. The frontend encrypts the private key
 * client-side before upload; the backend treats every field as opaque
 * ciphertext and never sees the master password or a decrypted private key.
 * Do not log instances of this record: it carries key material.
 */
public record UserKeyRegisterRequest(

        @NotNull
        @Size(min = 1, max = 1024)
        byte[] publicKey,

        @NotNull
        @Size(min = 1, max = 4096)
        byte[] encryptedPrivateKey,

        @NotNull
        @Size(min = 1, max = 128)
        byte[] privateKeyIv,

        @NotBlank
        @Size(max = 50)
        String kdfAlgorithm,

        @NotBlank
        @Size(max = 2000)
        String kdfParameters
) {
}