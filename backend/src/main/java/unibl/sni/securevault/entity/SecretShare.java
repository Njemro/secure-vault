package unibl.sni.securevault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One share of one secret with one recipient: only the DEK, wrapped with the
 * recipient's RSA-OAEP public key, is stored here. The encrypted content
 * stays in {@link Secret} and is never duplicated. Duplicates for the same
 * (secret, recipient) pair are rejected by uq_secret_shares_secret_recipient.
 */
@Entity
@Table(name = "secret_shares")
public class SecretShare {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "secret_id", nullable = false)
    private Secret secret;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "recipient_id", nullable = false)
    private User recipient;

    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "encrypted_dek", nullable = false, length = 1024)
    private byte[] encryptedDek;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    protected SecretShare() {
    }

    public SecretShare(Secret secret, User recipient, byte[] encryptedDek) {
        this.id = UUID.randomUUID();
        this.secret = secret;
        this.recipient = recipient;
        this.encryptedDek = encryptedDek;
        this.createdAt = LocalDateTime.now();
    }

    public UUID getId() {
        return id;
    }

    public Secret getSecret() {
        return secret;
    }

    public User getRecipient() {
        return recipient;
    }

    public byte[] getEncryptedDek() {
        return encryptedDek;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
}
