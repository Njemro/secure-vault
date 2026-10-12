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
 * Admin-configurable security policies (AGENTS.md section 10). Values must
 * never be hardcoded in application code; they are read from this table.
 * Enforced ranges live in the Flyway CHECK constraints.
 */
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

    @Column(name = "session_duration_minutes", nullable = false)
    private int sessionDurationMinutes;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected SecurityPolicy() {
    }

    public SecurityPolicy(int minMasterPasswordLength, int secretRotationIntervalDays,
                          int sessionDurationMinutes) {
        this.id = UUID.randomUUID();
        this.minMasterPasswordLength = minMasterPasswordLength;
        this.secretRotationIntervalDays = secretRotationIntervalDays;
        this.sessionDurationMinutes = sessionDurationMinutes;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    public UUID getId() {
        return id;
    }

    public int getMinMasterPasswordLength() {
        return minMasterPasswordLength;
    }

    public int getSecretRotationIntervalDays() {
        return secretRotationIntervalDays;
    }

    public int getSessionDurationMinutes() {
        return sessionDurationMinutes;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }
}
