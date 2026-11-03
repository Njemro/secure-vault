package unibl.sni.securevault.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

public record SecurityPolicyRequest(
        @Min(8) @Max(256) int minMasterPasswordLength,
        @Min(1) @Max(3650) int secretRotationIntervalDays,
        @Min(1) @Max(1440) int sessionInactivityTimeoutMinutes,
        @Min(1) @Max(10080) int maxSessionDurationMinutes
) {
}
