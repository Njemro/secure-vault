package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.Secret;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.repository.SecretRepository;
import unibl.sni.securevault.repository.UserRepository;

import java.util.List;
import java.util.UUID;

@Service
public class SecretService {

    private final SecretRepository secretRepository;
    private final UserRepository userRepository;

    public SecretService(SecretRepository secretRepository, UserRepository userRepository) {
        this.secretRepository = secretRepository;
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public List<Secret> findByOwnerId(UUID ownerId) {
        if (ownerId == null) {
            throw new InvalidOperationRequestException("ownerId must not be null");
        }
        return secretRepository.findByOwnerId(ownerId);
    }

    /**
     * Owner-scoped read: the secret is only returned when requestingOwnerId
     * matches the secret's owner. Controllers must pass the owner id obtained
     * from the authenticated security context, never from a client payload.
     */
    @Transactional(readOnly = true)
    public Secret getOwnedSecret(UUID secretId, UUID requestingOwnerId) {
        if (secretId == null || requestingOwnerId == null) {
            throw new InvalidOperationRequestException("secretId and requestingOwnerId must not be null");
        }
        Secret secret = secretRepository.findById(secretId)
                .orElseThrow(() -> new ResourceNotFoundException("Secret not found: " + secretId));
        if (!secret.getOwner().getId().equals(requestingOwnerId)) {
            throw new InvalidOperationRequestException("Requesting user does not own this secret");
        }
        return secret;
    }

    /**
     * Stores client-produced ciphertext only - the backend never receives
     * plaintext, the master password or an unwrapped DEK (AGENTS.md section 4).
     */
    @Transactional
    public Secret createSecret(UUID ownerId, String name, String description,
                               byte[] encryptedValue, byte[] encryptedDek,
                               byte[] contentIv, byte[] dekIv, String encryptionAlgorithm) {
        if (ownerId == null) {
            throw new InvalidOperationRequestException("ownerId must not be null");
        }
        if (name == null || name.isBlank()) {
            throw new InvalidOperationRequestException("name must not be blank");
        }
        if (encryptionAlgorithm == null || encryptionAlgorithm.isBlank()) {
            throw new InvalidOperationRequestException("encryptionAlgorithm must not be blank");
        }
        requireNonEmpty(encryptedValue, "encryptedValue");
        requireNonEmpty(encryptedDek, "encryptedDek");
        requireNonEmpty(contentIv, "contentIv");
        requireNonEmpty(dekIv, "dekIv");
        User owner = userRepository.findById(ownerId)
                .orElseThrow(() -> new ResourceNotFoundException("Owner not found: " + ownerId));
        return secretRepository.save(new Secret(
                owner, name, description,
                encryptedValue, encryptedDek, contentIv, dekIv, encryptionAlgorithm));
    }

    /**
     * Replaces an owned secret's metadata and ciphertext with fresh
     * client-produced values - the backend never receives plaintext, the
     * master password or an unwrapped DEK (AGENTS.md section 4). Ownership is
     * enforced through {@link #getOwnedSecret(UUID, UUID)}.
     */
    @Transactional
    public Secret updateOwnedSecret(UUID secretId, UUID requestingOwnerId, String name, String description,
                                    byte[] encryptedValue, byte[] encryptedDek,
                                    byte[] contentIv, byte[] dekIv, String encryptionAlgorithm) {
        if (secretId == null || requestingOwnerId == null) {
            throw new InvalidOperationRequestException("secretId and requestingOwnerId must not be null");
        }
        if (name == null || name.isBlank()) {
            throw new InvalidOperationRequestException("name must not be blank");
        }
        if (encryptionAlgorithm == null || encryptionAlgorithm.isBlank()) {
            throw new InvalidOperationRequestException("encryptionAlgorithm must not be blank");
        }
        requireNonEmpty(encryptedValue, "encryptedValue");
        requireNonEmpty(encryptedDek, "encryptedDek");
        requireNonEmpty(contentIv, "contentIv");
        requireNonEmpty(dekIv, "dekIv");
        Secret secret = getOwnedSecret(secretId, requestingOwnerId);
        secret.updateEncryptedContent(name, description, encryptedValue, encryptedDek,
                contentIv, dekIv, encryptionAlgorithm);
        return secretRepository.save(secret);
    }

    /**
     * Deletes an owned secret. Ownership is enforced through
     * {@link #getOwnedSecret(UUID, UUID)}; deleting an unknown secret is
     * reported as a missing resource, never silently ignored.
     */
    @Transactional
    public void deleteOwnedSecret(UUID secretId, UUID requestingOwnerId) {
        if (secretId == null || requestingOwnerId == null) {
            throw new InvalidOperationRequestException("secretId and requestingOwnerId must not be null");
        }
        Secret secret = getOwnedSecret(secretId, requestingOwnerId);
        secretRepository.delete(secret);
    }

    private static void requireNonEmpty(byte[] value, String field) {
        if (value == null || value.length == 0) {
            throw new InvalidOperationRequestException(field + " must not be empty");
        }
    }
}
