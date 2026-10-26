package unibl.sni.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.util.UUID;

/**
 * Request to verify a TOTP verification code during MFA enrollment or login.
 */
public record MfaVerifyRequest(
        @NotBlank
        @Pattern(regexp = "\\d{6}", message = "Verification code must be a 6-digit number")
        String code,

        UUID challengeId
) {
}