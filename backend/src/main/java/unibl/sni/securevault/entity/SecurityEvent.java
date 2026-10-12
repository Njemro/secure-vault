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
 * A security-relevant event (failed logins, suspicious requests, IP blocks,
 * honeypot access, ...). metadata must never contain secrets, passwords,
 * tokens or private keys.
 */
@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, updatable = false)
    private UUID id;

    /** Event timestamp (column name "event_time" avoids the TIMESTAMP keyword). */
    @Column(name = "event_time", nullable = false)
    private LocalDateTime timestamp;

    /** Nullable: some events are not tied to a user. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "event_type", nullable = false, length = 50)
    private String eventType;

    /** Nullable source IP; length 45 covers IPv6. */
    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    /** Safe metadata (JSON string). */
    @Column(nullable = false, length = 2000)
    private String metadata;

    protected SecurityEvent() {
    }

    public SecurityEvent(User user, String eventType, String sourceIp, String metadata) {
        this.id = UUID.randomUUID();
        this.timestamp = LocalDateTime.now();
        this.user = user;
        this.eventType = eventType;
        this.sourceIp = sourceIp;
        this.metadata = metadata;
    }

    public UUID getId() {
        return id;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public User getUser() {
        return user;
    }

    public String getEventType() {
        return eventType;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getMetadata() {
        return metadata;
    }
}
