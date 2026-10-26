package unibl.sni.securevault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Single-use, short-lived MFA challenge issued during login when MFA is
 * required. The challenge token is an opaque random identifier returned to the
 * client and presented (as a Bearer token) to {@code POST /api/auth/mfa/verify}.
 * It is <b>not</b> a JWT and cannot be used to access any protected API
 * endpoint - it is only looked up in this table to authorize MFA verification.
 * <p>Each challenge is bound to one user, expires after a fixed TTL, and may be
 * attempted only a limited number of times. On successful TOTP verification it
 * is marked as consumed and can never be used again.
 */
@Entity
@Table(name = "mfa_challenges")
public class MfaChallenge {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, updatable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, length = 36)
    @JdbcTypeCode(SqlTypes.CHAR)
    private UUID userId;

    @Column(name = "challenge_token", nullable = false, length = 36, unique = true)
    @JdbcTypeCode(SqlTypes.CHAR)
    private UUID challengeToken;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    @Column(name = "attempt_count", nullable = false)
    private int attemptCount;

    @Column(name = "max_attempts", nullable = false)
    private int maxAttempts;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    protected MfaChallenge() {
    }

    public MfaChallenge(UUID userId, UUID challengeToken, LocalDateTime expiresAt,
                        int maxAttempts) {
        this.id = UUID.randomUUID();
        this.userId = userId;
        this.challengeToken = challengeToken;
        this.expiresAt = expiresAt;
        this.usedAt = null;
        this.attemptCount = 0;
        this.maxAttempts = maxAttempts;
        this.createdAt = LocalDateTime.now();
    }

    public UUID getId() {
        return id;
    }

    public UUID getUserId() {
        return userId;
    }

    public UUID getChallengeToken() {
        return challengeToken;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public LocalDateTime getUsedAt() {
        return usedAt;
    }

    public int getAttemptCount() {
        return attemptCount;
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void markUsed() {
        this.usedAt = LocalDateTime.now();
    }

    public void incrementAttempts() {
        this.attemptCount++;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    public boolean isUsed() {
        return usedAt != null;
    }

    public boolean attemptsExceeded() {
        return attemptCount >= maxAttempts;
    }
}