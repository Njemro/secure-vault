package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.HoneypotSecret;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.repository.HoneypotSecretRepository;

import unibl.sni.securevault.entity.User;

import java.security.SecureRandom;
import java.util.Base64;

import java.util.List;
import java.util.UUID;

/**
 * Internal persistence and lookup for honeypot (decoy) records.
 * Honeypots are stored separately from ordinary secrets.
 * This service also provisions a decoy record for each user.
 */
@Service
public class HoneypotSecretService {

    private final HoneypotSecretRepository honeypotSecretRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    public HoneypotSecretService(HoneypotSecretRepository honeypotSecretRepository) {
        this.honeypotSecretRepository = honeypotSecretRepository;
    }

    @Transactional
    public HoneypotSecret persist(HoneypotSecret honeypotSecret) {
        if (honeypotSecret == null) {
            throw new InvalidOperationRequestException("honeypotSecret must not be null");
        }
        if (honeypotSecret.getOwner() == null) {
            throw new InvalidOperationRequestException("honeypot owner must not be null");
        }
        if (honeypotSecret.getName() == null || honeypotSecret.getName().isBlank()) {
            throw new InvalidOperationRequestException("honeypot name must not be blank");
        }
        if (honeypotSecret.getDecoyContent() == null || honeypotSecret.getDecoyContent().length == 0) {
            throw new InvalidOperationRequestException("honeypot decoy content must not be empty");
        }
        if (honeypotSecret.getMetadata() == null) {
            throw new InvalidOperationRequestException("honeypot metadata must not be null");
        }
        return honeypotSecretRepository.save(honeypotSecret);
    }

    @Transactional(readOnly = true)
    public HoneypotSecret getById(UUID honeypotId) {
        if (honeypotId == null) {
            throw new InvalidOperationRequestException("honeypotId must not be null");
        }
        return honeypotSecretRepository.findById(honeypotId)
                .orElseThrow(() -> new ResourceNotFoundException("Honeypot secret not found: " + honeypotId));
    }

    @Transactional(readOnly = true)
    public List<HoneypotSecret> findAll() {
        return honeypotSecretRepository.findAll();
    }


    @Transactional
    public void ensureHoneypotExists(User user) {
        if (user == null || user.getId() == null) {
            throw new InvalidOperationRequestException(
                    "A valid user is required to create a honeypot.");
        }
    
        if (honeypotSecretRepository.existsByOwnerId(user.getId())) {
            return;
        }
    
        byte[] decoyContent = new byte[128];
        secureRandom.nextBytes(decoyContent);
    
        String decoyName = "backup-credentials-" + UUID.randomUUID();
    
        String metadata = Base64.getEncoder()
                .encodeToString(randomBytes(24));
    
        HoneypotSecret honeypot = new HoneypotSecret(
                user,
                decoyName,
                decoyContent,
                null,
                metadata
        );
    
        honeypotSecretRepository.save(honeypot);
    }

    private byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}
