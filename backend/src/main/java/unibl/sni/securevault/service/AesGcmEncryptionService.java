package unibl.sni.securevault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Symmetric encryption (AES-256-GCM) for encrypting sensitive values at rest,
 * such as TOTP secrets. Uses a server-side master key derived from a configured
 * base64-encoded secret (or a generated development key).
 * <p>The master key is never persisted to the database. If the key is lost,
 * encrypted values cannot be recovered.
 */
@Service
public class AesGcmEncryptionService {

    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final String ALGORITHM = "AES/GCM/NoPadding";

    private final SecretKey key;

    public AesGcmEncryptionService(@Value("${vault.encryption.master-key:}") String base64MasterKey) {
        try {
            SecretKey key;
            if (base64MasterKey != null && !base64MasterKey.isBlank()) {
                byte[] keyBytes = Base64.getDecoder().decode(base64MasterKey);
                if (keyBytes.length != 32) {
                    throw new IllegalStateException("vault.encryption.master-key must decode to exactly 32 bytes");
                }
                key = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
            } else {
                // Development-only fallback: generate a random key at startup.
                // In production, VAULT_ENCRYPTION_MASTER_KEY must be set.
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(256);
                key = kg.generateKey();
            }
            this.key = key;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize encryption service", e);
        }
    }

    /** Encrypts plaintext bytes and returns ciphertext + IV. */
    public EncryptedSecret encrypt(byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_BYTES];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);
            return new EncryptedSecret(ciphertext, iv);
        } catch (Exception e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    /** Decrypts ciphertext using the supplied IV. */
    public byte[] decrypt(byte[] ciphertext, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("Decryption failed", e);
        }
    }

    /** Result of an encryption operation. */
    public record EncryptedSecret(byte[] ciphertext, byte[] iv) {
    }
}
