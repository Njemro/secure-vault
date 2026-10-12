package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
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
}
