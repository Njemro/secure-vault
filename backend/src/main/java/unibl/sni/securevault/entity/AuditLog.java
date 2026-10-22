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
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * One record of the SHA-256 audit hash chain (AGENTS.md section 12).
 * Hash-chain generation, ordering guarantees and tamper detection are
 * implemented in {@link unibl.sni.securevault.service.AuditLogService}, the
 * only production component that constructs records; it seals each record
 * with {@link #sealRecordHash(byte[])} immediately after construction.
 * metadata must contain only safe values: never secrets, encrypted contents,
 * passwords, keys, tokens or private keys. The schema alone does NOT make
 * records immutable; a database administrator able to rewrite the whole
 * chain remains outside what this design can defend against (documented in
 * AuditLogService).
 */
@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, updatable = false)
    private UUID id;

    /**
     * Event timestamp (column name "event_time" avoids the TIMESTAMP keyword).
     * Truncated to microseconds so the DATETIME(6) column stores it unchanged;
     * the record hash is computed over this value and must survive round-trips.
     */
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

    /** Hash of the previous chain record; 32 zero bytes (genesis) for the very first record. */
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
        // Microsecond truncation keeps the stored value byte-identical to the
        // value the record hash is computed over (DATETIME(6) precision).
        this.timestamp = LocalDateTime.now().truncatedTo(ChronoUnit.MICROS);
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

    /**
     * Seals this record with its computed SHA-256 hash. Called exactly once by
     * {@link unibl.sni.securevault.service.AuditLogService} right after
     * construction, while the constructor's all-zero placeholder is still in
     * place, so a stored record can never be re-hashed afterwards.
     */
    public void sealRecordHash(byte[] recordHash) {
        if (recordHash == null || recordHash.length != 32) {
            throw new IllegalArgumentException("recordHash must be exactly 32 bytes (SHA-256)");
        }
        if (this.recordHash == null || !isAllZero(this.recordHash)) {
            throw new IllegalStateException("audit record hash has already been sealed");
        }
        this.recordHash = recordHash;
    }

    private static boolean isAllZero(byte[] bytes) {
        for (byte b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
