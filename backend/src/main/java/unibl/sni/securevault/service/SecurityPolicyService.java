package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.dto.SecurityPolicyRequest;
import unibl.sni.securevault.entity.SecurityPolicy;
import unibl.sni.securevault.repository.SecurityPolicyRepository;

@Service
public class SecurityPolicyService {
    private final SecurityPolicyRepository repository;

    public SecurityPolicyService(SecurityPolicyRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public SecurityPolicy getCurrent() {
        return repository.findFirstByOrderByCreatedAtAsc()
                .orElseThrow(() -> new IllegalStateException(
                        "Security policy row is missing; apply Flyway migrations."));
    }

    @Transactional
    public SecurityPolicy update(SecurityPolicyRequest request) {
        SecurityPolicy current = getCurrent();
        current.update(
                request.minMasterPasswordLength(),
                request.secretRotationIntervalDays(),
                request.sessionInactivityTimeoutMinutes(),
                request.maxSessionDurationMinutes()
        );
        return repository.save(current);
    }
}
