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
 * Per-user cryptographic key material. The private key is stored only in its
 * client-side encrypted form; the server can never read it (AGENTS.md
 * section 6). Exactly one record per user (uq_user_keys_user_id).
 */
@Entity
@Table(name = "user_keys")
public class UserKey {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "public_key", nullable = false, length = 1024)
    private byte[] publicKey;

    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "encrypted_private_key", nullable = false, length = 4096)
    private byte[] encryptedPrivateKey;

    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "private_key_iv", nullable = false, length = 128)
    private byte[] privateKeyIv;

    @Column(name = "kdf_algorithm", nullable = false, length = 50)
    private String kdfAlgorithm;

    /** Non-secret KDF metadata (algorithm parameters, iteration count, salt) as JSON. */
    @Column(name = "kdf_parameters", nullable = false, length = 2000)
    private String kdfParameters;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    protected UserKey() {
    }

    public UserKey(User user, byte[] publicKey, byte[] encryptedPrivateKey, byte[] privateKeyIv,
                   String kdfAlgorithm, String kdfParameters) {
        this.id = UUID.randomUUID();
        this.user = user;
        this.publicKey = publicKey;
        this.encryptedPrivateKey = encryptedPrivateKey;
        this.privateKeyIv = privateKeyIv;
        this.kdfAlgorithm = kdfAlgorithm;
        this.kdfParameters = kdfParameters;
        this.createdAt = LocalDateTime.now();
    }

    public UUID getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    public byte[] getPrivateKeyIv() {
        return privateKeyIv;
    }

    public String getKdfAlgorithm() {
        return kdfAlgorithm;
    }

    public String getKdfParameters() {
        return kdfParameters;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
}
