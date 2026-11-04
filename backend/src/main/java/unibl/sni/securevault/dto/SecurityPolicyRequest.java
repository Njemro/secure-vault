package unibl.sni.securevault.dto;

import jakarta.validation.constraints.Min;

public record SecurityPolicyRequest(

        @Min(8)
        int minMasterPasswordLength,

        @Min(1)
        int secretRotationIntervalDays,

        @Min(1)
        int sessionInactivityTimeoutMinutes,

        @Min(1)
        int maxSessionDurationMinutes

) {
    // Kompatibilnost sa starim testovima i pozivima.
    public SecurityPolicyRequest(
            int minMasterPasswordLength,
            int secretRotationIntervalDays,
            int sessionInactivityTimeoutMinutes
    ) {
        this(
                minMasterPasswordLength,
                secretRotationIntervalDays,
                sessionInactivityTimeoutMinutes,
                600
        );
    }
}