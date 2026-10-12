package unibl.sni.securevault.dto;

import jakarta.validation.constraints.Min;

/**
 * Request to create or update a security policy. Constraints mirror the
 * schema CHECK constraints exactly (chk_security_policies_*); no default or
 * additional policy values are invented here.
 */
public record SecurityPolicyRequest(
        @Min(value = 8, message = "minMasterPasswordLength must be at least 8")
        int minMasterPasswordLength,
        @Min(value = 1, message = "secretRotationIntervalDays must be greater than 0")
        int secretRotationIntervalDays,
        @Min(value = 1, message = "sessionDurationMinutes must be greater than 0")
        int sessionDurationMinutes) {
}
