package unibl.sni.securevault.dto;

import java.time.LocalDateTime;
import java.util.UUID;

/** Current security policy values (admin-facing read model). */
public record SecurityPolicyResponse(
        UUID id,
        int minMasterPasswordLength,
        int secretRotationIntervalDays,
        int sessionDurationMinutes,
        LocalDateTime createdAt,
        LocalDateTime updatedAt) {
}
