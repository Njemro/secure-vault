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
 * Fake secret kept in a table of its own so ordinary Secret queries can never
 * expose honeypots (AGENTS.md section 13). Detection and response logic is
 * implemented in a later task; this entity only stores the decoy.
 */
@Entity
@Table(name = "honeypot_secrets")
public class HoneypotSecret {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @Column(nullable = false, length = 255)
    private String name;

    /** Decoy payload, safely represented (client-side encrypted or otherwise opaque bytes). */
    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "decoy_content", nullable = false, length = 50000)
    private byte[] decoyContent;

    /** Set only if the decoy content is encrypted; may be absent otherwise. */
    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "content_iv", length = 128)
    private byte[] contentIv;

    /** Safe identifying metadata for the decoy (JSON string, no secrets). */
    @Column(nullable = false, length = 1000)
    private String metadata;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    protected HoneypotSecret() {
    }

    public HoneypotSecret(User owner, String name, byte[] decoyContent, byte[] contentIv, String metadata) {
        this.id = UUID.randomUUID();
        this.owner = owner;
        this.name = name;
        this.decoyContent = decoyContent;
        this.contentIv = contentIv;
        this.metadata = metadata;
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

    public byte[] getDecoyContent() {
        return decoyContent;
    }

    public byte[] getContentIv() {
        return contentIv;
    }

    public String getMetadata() {
        return metadata;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
}
