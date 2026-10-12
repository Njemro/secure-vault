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
 * One record of the SHA-256 audit hash chain (AGENTS.md section 12).
 * Hash-chain calculation, writing and tamper detection are implemented in a
 * later task - this entity only stores the fields. metadata must contain
 * only safe values: never secrets, passwords, keys, tokens or private keys.
 * The schema alone does NOT make records immutable; immutability comes from
 * chain validation plus database protections.
 */
@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, updatable = false)
    private UUID id;

    /** Event timestamp (column name "event_time" avoids the TIMESTAMP keyword). */
    @Column(name = "event_time", nullable = false)
    private LocalDateTime timestamp;

    /** Nullable: system-generated events have no actor. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "actor_id")
    private User actor;

    @Column(nullable = false, length = 50)
    private String action;

    @Column(name = "resource_type", nullable = false, length = 50)
    private String resourceType;

    @Column(name = "resource_id", length = 64)
    private String resourceId;

    /** Safe, non-sensitive metadata (JSON string). */
    @Column(nullable = false, length = 2000)
    private String metadata;

    /** Hash of the previous chain record; the chain-writer task defines the genesis value. */
    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "previous_hash", nullable = false, length = 32)
    private byte[] previousHash;

    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "record_hash", nullable = false, length = 32)
    private byte[] recordHash;

    protected AuditLog() {
    }

    public AuditLog(User actor, String action, String resourceType, String resourceId,
                    String metadata, byte[] previousHash, byte[] recordHash) {
        this.id = UUID.randomUUID();
        this.timestamp = LocalDateTime.now();
        this.actor = actor;
        this.action = action;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.metadata = metadata;
        this.previousHash = previousHash;
        this.recordHash = recordHash;
    }

    public UUID getId() {
        return id;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public User getActor() {
        return actor;
    }

    public String getAction() {
        return action;
    }

    public String getResourceType() {
        return resourceType;
    }

    public String getResourceId() {
        return resourceId;
    }

    public String getMetadata() {
        return metadata;
    }

    public byte[] getPreviousHash() {
        return previousHash;
    }

    public byte[] getRecordHash() {
        return recordHash;
    }
}
