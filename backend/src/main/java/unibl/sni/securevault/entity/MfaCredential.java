package unibl.sni.securevault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Encrypted TOTP credential for a user's multi-factor authentication.
 * <p>The Base32-encoded TOTP secret is encrypted at rest (AES-256-GCM) using
 * a server-side key before being persisted. The plaintext secret and
 * verification codes are never logged.
 * <p>One record per user; existence of the record means MFA is enrolled but
 * {@link User#isMfaEnabled()} controls whether MFA is enforced at login.
 */
@Entity
@Table(name = "mfa_credentials")
public class MfaCredential {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, updatable = false)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /**
     * AES-256-GCM encrypted TOTP secret (Base32 text), never plaintext.
     */
    @Column(name = "encrypted_secret", nullable = false, length = 4096)
    private byte[] encryptedSecret;

    @Column(name = "secret_iv", nullable = false, length = 128)
    private byte[] secretIv;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected MfaCredential() {
    }

    public MfaCredential(User user, byte[] encryptedSecret, byte[] secretIv) {
        this.id = UUID.randomUUID();
        this.user = user;
        this.encryptedSecret = encryptedSecret;
        this.secretIv = secretIv;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    public UUID getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public byte[] getEncryptedSecret() {
        return encryptedSecret;
    }

    public void setEncryptedSecret(byte[] encryptedSecret) {
        this.encryptedSecret = encryptedSecret;
    }

    public byte[] getSecretIv() {
        return secretIv;
    }

    public void setSecretIv(byte[] secretIv) {
        this.secretIv = secretIv;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
