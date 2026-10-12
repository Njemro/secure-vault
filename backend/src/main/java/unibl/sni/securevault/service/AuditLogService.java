package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.AuditLog;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.repository.AuditLogRepository;

/**
 * Minimal audit persistence. Hash-chain generation, ordering guarantees and
 * tamper detection are implemented in a later task; nothing here claims the
 * records are immutable. Audit metadata must never contain secrets,
 * passwords, keys or tokens (AGENTS.md section 12).
 */
@Service
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    public AuditLogService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Transactional
    public AuditLog persist(AuditLog auditLog) {
        if (auditLog == null) {
            throw new InvalidOperationRequestException("auditLog must not be null");
        }
        if (auditLog.getAction() == null || auditLog.getAction().isBlank()) {
            throw new InvalidOperationRequestException("audit action must not be blank");
        }
        if (auditLog.getResourceType() == null || auditLog.getResourceType().isBlank()) {
            throw new InvalidOperationRequestException("audit resourceType must not be blank");
        }
        if (auditLog.getMetadata() == null) {
            throw new InvalidOperationRequestException("audit metadata must not be null");
        }
        if (auditLog.getPreviousHash() == null || auditLog.getPreviousHash().length == 0
                || auditLog.getRecordHash() == null || auditLog.getRecordHash().length == 0) {
            throw new InvalidOperationRequestException("audit hashes must not be empty");
        }
        return auditLogRepository.save(auditLog);
    }
}
