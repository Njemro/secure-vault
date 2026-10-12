package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.SecurityEvent;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.repository.SecurityEventRepository;

import java.util.List;
import java.util.UUID;

/**
 * Persists and retrieves security-relevant events. Event metadata must never
 * contain secrets, passwords, tokens or private keys.
 */
@Service
public class SecurityEventService {

    private final SecurityEventRepository securityEventRepository;

    public SecurityEventService(SecurityEventRepository securityEventRepository) {
        this.securityEventRepository = securityEventRepository;
    }

    @Transactional
    public SecurityEvent persist(SecurityEvent securityEvent) {
        if (securityEvent == null) {
            throw new InvalidOperationRequestException("securityEvent must not be null");
        }
        if (securityEvent.getEventType() == null || securityEvent.getEventType().isBlank()) {
            throw new InvalidOperationRequestException("eventType must not be blank");
        }
        if (securityEvent.getMetadata() == null) {
            throw new InvalidOperationRequestException("event metadata must not be null");
        }
        return securityEventRepository.save(securityEvent);
    }

    @Transactional(readOnly = true)
    public List<SecurityEvent> findByUserId(UUID userId) {
        if (userId == null) {
            throw new InvalidOperationRequestException("userId must not be null");
        }
        return securityEventRepository.findByUserIdOrderByTimestampDesc(userId);
    }

    @Transactional(readOnly = true)
    public List<SecurityEvent> findAll() {
        return securityEventRepository.findAll();
    }
}
