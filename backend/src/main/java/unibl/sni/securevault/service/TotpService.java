package unibl.sni.securevault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Time-Based One-Time Password (TOTP) generation and verification per RFC 6238.
 * <p>Uses standard Java cryptography (HMAC-SHA-1) - no custom cryptographic
 * algorithms are implemented. The TOTP secret is treated as sensitive key
 * material and must never be logged or returned to the client after enrollment.
 */
@Service
public class TotpService {

    private static final int CODE_DIGITS = 6;
    private static final long TIME_STEP_SECONDS = 30;
    private static final int MODULUS = 1_000_000;

    private static final char[] BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    private final String totpIssuer;

    public TotpService(@Value("${vault.mfa.totp.issuer:Secure Vault}") String totpIssuer) {
        this.totpIssuer = totpIssuer;
    }

    /** Generates a random Base32-encoded TOTP secret (160 bits / 20 bytes). */
    public String generateSecret() {
        byte[] randomBytes = new byte[20];
        new SecureRandom().nextBytes(randomBytes);
        return base32Encode(randomBytes);
    }

    /** Builds an {@code otpauth://totp/} provisioning URI for authenticator apps. */
    public String provisioningUri(String username, String secret) {
        String encodedUsername = java.net.URLEncoder.encode(username, StandardCharsets.UTF_8);
        String encodedIssuer = java.net.URLEncoder.encode(totpIssuer, StandardCharsets.UTF_8);
        return "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d"
                .formatted(encodedIssuer, encodedUsername, secret, encodedIssuer, CODE_DIGITS, TIME_STEP_SECONDS);
    }

    /** Validates a 6-digit TOTP code with a ±1 time-step clock-skew window. */
    public boolean verifyCode(String secret, String code) {
        if (secret == null || secret.isBlank() || code == null || code.isBlank()) {
            return false;
        }
        if (!code.matches("\\d{6}")) {
            return false;
        }
        byte[] key;
        try {
            key = base32Decode(secret);
        } catch (IllegalArgumentException e) {
            return false;
        }
        long currentTimeStep = System.currentTimeMillis() / 1000 / TIME_STEP_SECONDS;
        for (long offset : new long[]{-1, 0, 1}) {
            long codeValue = generateCode(key, currentTimeStep + offset);
            if (constantTimeEquals(formatCode(codeValue), code)) {
                return true;
            }
        }
        return false;
    }

    private long generateCode(byte[] key, long timeStep) {
        try {
            byte[] timeBytes = longToBigEndianBytes(timeStep);
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(timeBytes);
            int offset = hash[hash.length - 1] & 0x0F;
            int binary =
                    ((hash[offset] & 0x7F) << 24) |
                            ((hash[offset + 1] & 0xFF) << 16) |
                            ((hash[offset + 2] & 0xFF) << 8) |
                            (hash[offset + 3] & 0xFF);
            return binary % MODULUS;
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA-1 is not available on this platform", e);
        }
    }

    private static String formatCode(long codeValue) {
        return String.format("%06d", codeValue);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    private static byte[] longToBigEndianBytes(long value) {
        byte[] bytes = new byte[8];
        for (int i = 7; i >= 0; i--) {
            bytes[i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
        return bytes;
    }

    // -------------------------------------------------------------------------
    // Base32 (RFC 4648)
    // -------------------------------------------------------------------------

    private static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int bits = 0;
        int value = 0;
        for (byte b : data) {
            value = (value << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                sb.append(BASE32_ALPHABET[(value >> (bits - 5)) & 0x1F]);
                bits -= 5;
            }
        }
        if (bits > 0) {
            sb.append(BASE32_ALPHABET[(value << (5 - bits)) & 0x1F]);
        }
        while (sb.length() % 8 != 0) {
            sb.append('=');
        }
        return sb.toString();
    }

    private static byte[] base32Decode(String encoded) {
        encoded = encoded.trim().replace("=", "").toUpperCase();
        byte[] data = new byte[encoded.length() * 5 / 8];
        int index = 0;
        int bits = 0;
        int value = 0;
        for (int i = 0; i < encoded.length(); i++) {
            char c = encoded.charAt(i);
            int digit;
            if (c >= 'A' && c <= 'Z') {
                digit = c - 'A';
            } else if (c >= '2' && c <= '7') {
                digit = c - '2' + 26;
            } else {
                throw new IllegalArgumentException("Invalid Base32 character: " + c);
            }
            value = (value << 5) | digit;
            bits += 5;
            if (bits >= 8) {
                data[index++] = (byte) ((value >> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return data;
    }
}
