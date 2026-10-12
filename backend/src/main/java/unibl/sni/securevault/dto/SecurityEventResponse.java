package unibl.sni.securevault.dto;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Read-only view of a security event (admin-facing). There is deliberately
 * no event-create request DTO: events are produced internally by the
 * backend/gateway, never submitted by clients. {@code userId} is nullable.
 * Metadata contains only safe, non-sensitive values.
 */
public record SecurityEventResponse(
        UUID id,
        LocalDateTime timestamp,
        UUID userId,
        String eventType,
        String sourceIp,
        String metadata) {
}
