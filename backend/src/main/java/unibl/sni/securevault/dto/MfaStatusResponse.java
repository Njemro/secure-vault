package unibl.sni.securevault.dto;

/**
 * Current MFA status for the authenticated user.
 */
public record MfaStatusResponse(
        boolean mfaEnrolled,
        boolean mfaEnabled
) {
}