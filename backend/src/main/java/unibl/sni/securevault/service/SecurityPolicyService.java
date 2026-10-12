package unibl.sni.securevault.service;

import org.springframework.beans.DirectFieldAccessor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.SecurityPolicy;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.repository.SecurityPolicyRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class SecurityPolicyService {

    private final SecurityPolicyRepository securityPolicyRepository;

    public SecurityPolicyService(SecurityPolicyRepository securityPolicyRepository) {
        this.securityPolicyRepository = securityPolicyRepository;
    }

    @Transactional(readOnly = true)
    public List<SecurityPolicy> findAll() {
        return securityPolicyRepository.findAll();
    }

    @Transactional(readOnly = true)
    public SecurityPolicy getById(UUID policyId) {
        if (policyId == null) {
            throw new InvalidOperationRequestException("policyId must not be null");
        }
        return securityPolicyRepository.findById(policyId)
                .orElseThrow(() -> new ResourceNotFoundException("Security policy not found: " + policyId));
    }

    /**
     * Creates a policy row. No default values are invented - callers supply
     * every value; ranges mirror the schema CHECK constraints.
     */
    @Transactional
    public SecurityPolicy create(int minMasterPasswordLength, int secretRotationIntervalDays,
                                 int sessionDurationMinutes) {
        validatePolicyValues(minMasterPasswordLength, secretRotationIntervalDays, sessionDurationMinutes);
        return securityPolicyRepository.save(
                new SecurityPolicy(minMasterPasswordLength, secretRotationIntervalDays, sessionDurationMinutes));
    }

    /**
     * Replaces all three policy values on an existing row (partial updates
     * are not supported - simplest defensible contract). The entities expose
     * no setters and entity changes are out of scope for this task, so the
     * managed entity's fields are written directly; JPA dirty checking then
     * issues the UPDATE on flush.
     */
    @Transactional
    public SecurityPolicy update(UUID policyId, int minMasterPasswordLength,
                                 int secretRotationIntervalDays, int sessionDurationMinutes) {
        if (policyId == null) {
            throw new InvalidOperationRequestException("policyId must not be null");
        }
        validatePolicyValues(minMasterPasswordLength, secretRotationIntervalDays, sessionDurationMinutes);
        SecurityPolicy policy = securityPolicyRepository.findById(policyId)
                .orElseThrow(() -> new ResourceNotFoundException("Security policy not found: " + policyId));

        DirectFieldAccessor accessor = new DirectFieldAccessor(policy);
        accessor.setPropertyValue("minMasterPasswordLength", minMasterPasswordLength);
        accessor.setPropertyValue("secretRotationIntervalDays", secretRotationIntervalDays);
        accessor.setPropertyValue("sessionDurationMinutes", sessionDurationMinutes);
        accessor.setPropertyValue("updatedAt", LocalDateTime.now());
        return securityPolicyRepository.save(policy);
    }

    /** Mirrors the schema CHECK constraints (chk_security_policies_*). */
    private static void validatePolicyValues(int minMasterPasswordLength, int secretRotationIntervalDays,
                                             int sessionDurationMinutes) {
        if (minMasterPasswordLength < 8) {
            throw new InvalidOperationRequestException(
                    "minMasterPasswordLength must be at least 8 (schema constraint)");
        }
        if (secretRotationIntervalDays <= 0) {
            throw new InvalidOperationRequestException(
                    "secretRotationIntervalDays must be greater than 0 (schema constraint)");
        }
        if (sessionDurationMinutes <= 0) {
            throw new InvalidOperationRequestException(
                    "sessionDurationMinutes must be greater than 0 (schema constraint)");
        }
    }
}
