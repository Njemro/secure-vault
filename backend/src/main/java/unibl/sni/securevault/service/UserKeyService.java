package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserKey;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.repository.UserKeyRepository;

import java.util.Optional;
import java.util.UUID;

@Service
public class UserKeyService {

    private final UserKeyRepository userKeyRepository;

    public UserKeyService(UserKeyRepository userKeyRepository) {
        this.userKeyRepository = userKeyRepository;
    }

    /**
     * Returns the user's key record (public key plus client-side encrypted
     * private key) or empty when the user has none. The server never holds
     * plaintext private keys (AGENTS.md section 6).
     */
    @Transactional(readOnly = true)
    public Optional<UserKey> findByUserId(UUID userId) {
        if (userId == null) {
            throw new InvalidOperationRequestException("userId must not be null");
        }
        return userKeyRepository.findByUserId(userId);
    }

    /**
     * Registers or replaces the authenticated user's key material. Because
     * {@code user_keys.user_id} is unique ({@code uq_user_keys_user_id}),
     * calling this for a user who already has a record overwrites that record
     * in place - the caller can only ever touch their own keys since the user
     * is resolved from the JWT {@code sub} claim, never from request input.
     * <p>All cryptographic values are opaque client-produced bytes; the
     * backend never generates, unwraps, decrypts or re-encrypts them.
     */
    @Transactional
    public UserKey registerOrUpdateKeys(User user, byte[] publicKey,
                                        byte[] encryptedPrivateKey,
                                        byte[] privateKeyIv,
                                        String kdfAlgorithm,
                                        String kdfParameters) {
        if (user == null) {
            throw new InvalidOperationRequestException("user must not be null");
        }
        if (publicKey == null || publicKey.length == 0) {
            throw new InvalidOperationRequestException("publicKey must not be empty");
        }
        if (encryptedPrivateKey == null || encryptedPrivateKey.length == 0) {
            throw new InvalidOperationRequestException("encryptedPrivateKey must not be empty");
        }
        if (privateKeyIv == null || privateKeyIv.length == 0) {
            throw new InvalidOperationRequestException("privateKeyIv must not be empty");
        }
        if (kdfAlgorithm == null || kdfAlgorithm.isBlank()) {
            throw new InvalidOperationRequestException("kdfAlgorithm must not be blank");
        }
        if (kdfParameters == null || kdfParameters.isBlank()) {
            throw new InvalidOperationRequestException("kdfParameters must not be blank");
        }

        return userKeyRepository.findByUserId(user.getId())
                .map(existing -> {
                    existing.setPublicKey(publicKey);
                    existing.setEncryptedPrivateKey(encryptedPrivateKey);
                    existing.setPrivateKeyIv(privateKeyIv);
                    existing.setKdfAlgorithm(kdfAlgorithm);
                    existing.setKdfParameters(kdfParameters);
                    return userKeyRepository.save(existing);
                })
                .orElseGet(() -> userKeyRepository.save(new UserKey(
                        user, publicKey, encryptedPrivateKey, privateKeyIv,
                        kdfAlgorithm, kdfParameters)));
    }
}
