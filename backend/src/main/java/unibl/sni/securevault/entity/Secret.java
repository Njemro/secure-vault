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
 * An encrypted secret owned directly by a user (no separate Vault entity).
 * All cryptographic values are opaque bytes produced client-side; the
 * backend never sees plaintext, KEKs or unwrapped DEKs (AGENTS.md section 4).
 */
@Entity
@Table(name = "secrets")
public class Secret {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @Column(nullable = false, length = 255)
    private String name;

    @Column(length = 1000)
    private String description;

    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "encrypted_value", nullable = false, length = 50000)
    private byte[] encryptedValue;

    /** The DEK wrapped with AES-256-GCM under the owner's KEK. */
    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "encrypted_dek", nullable = false, length = 1024)
    private byte[] encryptedDek;

    /** Fresh 12-byte IV used for the AES-GCM encryption of the secret content. */
    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "content_iv", nullable = false, length = 128)
    private byte[] contentIv;

    /** IV used for the AES-GCM DEK wrapping - must differ from contentIv. */
    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "dek_iv", nullable = false, length = 128)
    private byte[] dekIv;

    @Column(name = "encryption_algorithm", nullable = false, length = 50)
    private String encryptionAlgorithm;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_rotated_at")
    private LocalDateTime lastRotatedAt;

    protected Secret() {
    }

    public Secret(User owner, String name, String description, byte[] encryptedValue, byte[] encryptedDek,
                  byte[] contentIv, byte[] dekIv, String encryptionAlgorithm) {
        this.id = UUID.randomUUID();
        this.owner = owner;
        this.name = name;
        this.description = description;
        this.encryptedValue = encryptedValue;
        this.encryptedDek = encryptedDek;
        this.contentIv = contentIv;
        this.dekIv = dekIv;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.createdAt = LocalDateTime.now();
    }

    public UUID getId() {
        return id;
    }

    public User getOwner() {
        return owner;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public byte[] getEncryptedValue() {
        return encryptedValue;
    }

    public byte[] getEncryptedDek() {
        return encryptedDek;
    }

    public byte[] getContentIv() {
        return contentIv;
    }

    public byte[] getDekIv() {
        return dekIv;
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getLastRotatedAt() {
        return lastRotatedAt;
    }

    /**
     * Applies a full client-side re-encryption of this secret's content and
     * wrapped DEK (PUT semantics). All values are opaque ciphertext and IVs
     * produced in the browser; the backend never decrypts, unwraps or
     * re-encrypts any of them (AGENTS.md section 4). Replacing the encrypted
     * payload counts as a rotation, so {@code lastRotatedAt} is stamped.
     */
    public void updateEncryptedContent(String name, String description, byte[] encryptedValue,
                                       byte[] encryptedDek, byte[] contentIv, byte[] dekIv,
                                       String encryptionAlgorithm) {
        this.name = name;
        this.description = description;
        this.encryptedValue = encryptedValue;
        this.encryptedDek = encryptedDek;
        this.contentIv = contentIv;
        this.dekIv = dekIv;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.lastRotatedAt = LocalDateTime.now();
    }
}
