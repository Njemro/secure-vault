package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.dto.SecurityPolicyRequest;
import unibl.sni.securevault.entity.SecurityPolicy;
import unibl.sni.securevault.repository.SecurityPolicyRepository;

import java.util.UUID;
import unibl.sni.securevault.exception.ResourceNotFoundException;

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

    // Odavdje je dodato zbog kompatibilnosti sa starim testovima i pozivima.

    @Transactional(readOnly = true)
    public SecurityPolicy getById(UUID policyId) {
        return repository.findById(policyId)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "Security policy not found: " + policyId
                        )
                );
    }

    @Transactional
    public SecurityPolicy create(
            int minMasterPasswordLength,
            int secretRotationIntervalDays,
            int sessionDurationMinutes
    ) {
        validate(
                minMasterPasswordLength,
                secretRotationIntervalDays,
                sessionDurationMinutes,
                600
        );

        SecurityPolicy policy = new SecurityPolicy(
                minMasterPasswordLength,
                secretRotationIntervalDays,
                sessionDurationMinutes,
                600
        );

        return repository.save(policy);
    }

    @Transactional
    public SecurityPolicy update(
            UUID policyId,
            int minMasterPasswordLength,
            int secretRotationIntervalDays,
            int sessionDurationMinutes
    ) {
        SecurityPolicy policy = getById(policyId);

        validate(
                minMasterPasswordLength,
                secretRotationIntervalDays,
                sessionDurationMinutes,
                policy.getMaxSessionDurationMinutes()
        );

        policy.update(
                minMasterPasswordLength,
                secretRotationIntervalDays,
                sessionDurationMinutes,
                policy.getMaxSessionDurationMinutes()
        );

        return repository.save(policy);
    }

    private void validate(
            int minMasterPasswordLength,
            int secretRotationIntervalDays,
            int sessionInactivityTimeoutMinutes,
            int maxSessionDurationMinutes
    ) {
        if (minMasterPasswordLength < 8) {
            throw new IllegalArgumentException(
                    "Minimum master password length must be at least 8."
            );
        }
    
        if (secretRotationIntervalDays < 1) {
            throw new IllegalArgumentException(
                    "Secret rotation interval must be at least 1 day."
            );
        }
    
        if (sessionInactivityTimeoutMinutes < 1) {
            throw new IllegalArgumentException(
                    "Session inactivity timeout must be at least 1 minute."
            );
        }
    
        if (maxSessionDurationMinutes < 1) {
            throw new IllegalArgumentException(
                    "Maximum session duration must be at least 1 minute."
            );
        }
    
        if (maxSessionDurationMinutes < sessionInactivityTimeoutMinutes) {
            throw new IllegalArgumentException(
                    "Maximum session duration cannot be shorter than inactivity timeout."
            );
        }
    }
}
