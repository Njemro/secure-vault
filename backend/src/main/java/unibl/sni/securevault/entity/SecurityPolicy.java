package unibl.sni.securevault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "security_policies")
public class SecurityPolicy {
    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, updatable = false)
    private UUID id;

    @Column(name = "min_master_password_length", nullable = false)
    private int minMasterPasswordLength;

    @Column(name = "secret_rotation_interval_days", nullable = false)
    private int secretRotationIntervalDays;

    // Legacy DB/API name retained; this is the inactivity timeout.
    @Column(name = "session_duration_minutes", nullable = false)
    private int sessionDurationMinutes;

    @Column(name = "max_session_duration_minutes", nullable = false)
    private int maxSessionDurationMinutes;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected SecurityPolicy() {}

    public SecurityPolicy(int minMasterPasswordLength,
                          int secretRotationIntervalDays,
                          int sessionDurationMinutes,
                          int maxSessionDurationMinutes) {
        this.id = UUID.randomUUID();
        this.minMasterPasswordLength = minMasterPasswordLength;
        this.secretRotationIntervalDays = secretRotationIntervalDays;
        this.sessionDurationMinutes = sessionDurationMinutes;
        this.maxSessionDurationMinutes = maxSessionDurationMinutes;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = this.createdAt;
    }

    public void update(int minMasterPasswordLength, int secretRotationIntervalDays,
                       int sessionDurationMinutes, int maxSessionDurationMinutes) {
        this.minMasterPasswordLength = minMasterPasswordLength;
        this.secretRotationIntervalDays = secretRotationIntervalDays;
        this.sessionDurationMinutes = sessionDurationMinutes;
        this.maxSessionDurationMinutes = maxSessionDurationMinutes;
        this.updatedAt = LocalDateTime.now();
    }

    public UUID getId() { return id; }
    public int getMinMasterPasswordLength() { return minMasterPasswordLength; }
    public int getSecretRotationIntervalDays() { return secretRotationIntervalDays; }
    public int getSessionDurationMinutes() { return sessionDurationMinutes; }
    public int getMaxSessionDurationMinutes() { return maxSessionDurationMinutes; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
}
