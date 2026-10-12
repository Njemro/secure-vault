package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.HoneypotSecret;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.repository.HoneypotSecretRepository;

import java.util.List;
import java.util.UUID;

/**
 * Internal persistence and lookup for honeypot (decoy) records only.
 * Honeypots live in their own table and repository, so they can never appear
 * in ordinary secret queries; detection and response logic is a later task
 * (AGENTS.md section 13).
 */
@Service
public class HoneypotSecretService {

    private final HoneypotSecretRepository honeypotSecretRepository;

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
}
