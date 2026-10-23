package unibl.sni.securevault.dto;

/**
 * Response to MFA enrollment start. Carries the provisioning URI (for QR code)
 * and the raw Base32 secret (shown only once, for manual entry).
 * <p>The secret field is sensitive: it must not be logged.
 */
public record MfaEnrollResponse(
        String provisioningUri,
        String secret
) {
}