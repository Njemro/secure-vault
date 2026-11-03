package unibl.sni.securevault.dto;

import unibl.sni.securevault.entity.SecurityPolicy;

import java.time.LocalDateTime;
import java.util.UUID;

public record SecurityPolicyResponse(
        UUID id,
        int minMasterPasswordLength,
        int secretRotationIntervalDays,
        int sessionInactivityTimeoutMinutes,
        int maxSessionDurationMinutes,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
    public static SecurityPolicyResponse from(SecurityPolicy policy) {
        return new SecurityPolicyResponse(
                policy.getId(),
                policy.getMinMasterPasswordLength(),
                policy.getSecretRotationIntervalDays(),
                policy.getSessionDurationMinutes(),
                policy.getMaxSessionDurationMinutes(),
                policy.getCreatedAt(),
                policy.getUpdatedAt()
        );
    }
}
