package unibl.sni.securevault.dto;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Read-only view of an audit record for the internal/admin audit interface.
 * There is deliberately no audit-create request DTO: audit records are
 * internal security records written by the backend, never by clients.
 * {@code actorId} is nullable (system-generated events). Hashes are raw
 * SHA-256 bytes; expected as Base64 at the JSON API boundary.
 * Metadata is guaranteed to contain only safe, non-sensitive values.
 */
public record AuditLogResponse(
        UUID id,
        LocalDateTime timestamp,
        UUID actorId,
        String action,
        String resourceType,
        String resourceId,
        String metadata,
        byte[] previousHash,
        byte[] recordHash) {
}
