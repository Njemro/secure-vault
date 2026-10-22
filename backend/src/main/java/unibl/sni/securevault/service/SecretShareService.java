package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.Secret;
import unibl.sni.securevault.entity.SecretShare;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.repository.SecretRepository;
import unibl.sni.securevault.repository.SecretShareRepository;
import unibl.sni.securevault.repository.UserKeyRepository;
import unibl.sni.securevault.repository.UserRepository;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
public class SecretShareService {

    private final SecretRepository secretRepository;
    private final SecretShareRepository secretShareRepository;
    private final UserRepository userRepository;
    private final UserKeyRepository userKeyRepository;

    public SecretShareService(SecretRepository secretRepository,
                              SecretShareRepository secretShareRepository,
                              UserRepository userRepository,
                              UserKeyRepository userKeyRepository) {
        this.secretRepository = secretRepository;
        this.secretShareRepository = secretShareRepository;
        this.userRepository = userRepository;
        this.userKeyRepository = userKeyRepository;
    }

    @Transactional(readOnly = true)
    public List<SecretShare> findByRecipientId(UUID recipientId) {
        if (recipientId == null) {
            throw new InvalidOperationRequestException("recipientId must not be null");
        }
        return secretShareRepository.findByRecipientId(recipientId);
    }

    @Transactional(readOnly = true)
    public List<SecretShare> findBySecretId(UUID secretId) {
        if (secretId == null) {
            throw new InvalidOperationRequestException("secretId must not be null");
        }
        return secretShareRepository.findBySecretId(secretId);
    }

    @Transactional(readOnly = true)
    public List<SecretShare> findByRecipientIdWithSecretAndOwner(UUID recipientId) {
        if (recipientId == null) {
            throw new InvalidOperationRequestException("recipientId must not be null");
        }
        return secretShareRepository.findByRecipientIdWithSecretAndOwner(recipientId);
    }

    @Transactional(readOnly = true)
    public Optional<SecretShare> findShareBySecretAndRecipient(UUID secretId, UUID recipientId) {
        if (secretId == null || recipientId == null) {
            throw new InvalidOperationRequestException("secretId and recipientId must not be null");
        }
        return secretShareRepository.findBySecretIdAndRecipientId(secretId, recipientId);
    }

    /**
     * Shares one secret with several recipients in a single atomic operation.
     *
     * <p>Each recipient's entry already contains the DEK wrapped by the
     * sharing client (RSA-OAEP with the recipient's public key). This service
     * performs no cryptography and never sees an unwrapped DEK. The secret's
     * encrypted content is not modified by sharing.
     *
     * <p>All recipients are validated before anything is persisted and the
     * whole operation runs in one transaction, so a failure never leaves a
     * partial set of shares. Controllers must pass sharingOwnerId from the
     * authenticated security context, never from a client payload.
     *
     * @param recipientIds        recipients in request order
     * @param recipientEncryptedDeks recipient-encrypted DEK per recipient, same order and size
     */
    @Transactional
    public List<SecretShare> createShares(UUID secretId, UUID sharingOwnerId,
                                          List<UUID> recipientIds,
                                          List<byte[]> recipientEncryptedDeks) {
        if (secretId == null || sharingOwnerId == null) {
            throw new InvalidOperationRequestException("secretId and sharingOwnerId must not be null");
        }
        if (recipientIds == null || recipientIds.isEmpty()) {
            throw new InvalidOperationRequestException("at least one recipient is required");
        }
        if (recipientEncryptedDeks == null || recipientEncryptedDeks.size() != recipientIds.size()) {
            throw new InvalidOperationRequestException(
                    "an encrypted DEK is required for every recipient");
        }

        Secret secret = secretRepository.findById(secretId)
                .orElseThrow(() -> new ResourceNotFoundException("Secret not found: " + secretId));
        if (!secret.getOwner().getId().equals(sharingOwnerId)) {
            throw new InvalidOperationRequestException("Only the secret owner can share this secret");
        }

        // Validate every recipient before persisting anything.
        Set<UUID> seen = new HashSet<>();
        List<SecretShare> shares = new ArrayList<>();
        for (int i = 0; i < recipientIds.size(); i++) {
            UUID recipientId = recipientIds.get(i);
            byte[] encryptedDek = recipientEncryptedDeks.get(i);
            if (recipientId == null) {
                throw new InvalidOperationRequestException("recipient id must not be null");
            }
            if (!seen.add(recipientId)) {
                throw new InvalidOperationRequestException("duplicate recipient: " + recipientId);
            }
            if (recipientId.equals(sharingOwnerId)) {
                throw new InvalidOperationRequestException(
                        "a secret cannot be shared with its own owner");
            }
            if (encryptedDek == null || encryptedDek.length == 0) {
                throw new InvalidOperationRequestException(
                        "encrypted DEK must not be empty for recipient: " + recipientId);
            }
            User recipient = userRepository.findById(recipientId)
                    .orElseThrow(() -> new ResourceNotFoundException(
                            "Recipient not found: " + recipientId));
            userKeyRepository.findByUserId(recipientId)
                    .orElseThrow(() -> new ResourceNotFoundException(
                            "Recipient has no key record: " + recipientId));
            shares.add(new SecretShare(secret, recipient, encryptedDek));
        }

        return secretShareRepository.saveAll(shares);
    }
}
