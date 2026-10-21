package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import unibl.sni.securevault.entity.AuditLog;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.repository.AuditLogRepository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Writes and validates the SHA-256 audit hash chain (AGENTS.md section 12).
 *
 * <p>Every record stores {@code previousHash} = the previous record's
 * {@code recordHash} (32 zero bytes - the genesis value - for the very first
 * record) and {@code recordHash} = SHA-256 over a deterministic canonical
 * representation of the record that includes {@code previousHash}. The
 * canonical form is the NUL-separated concatenation of: record id, timestamp,
 * actor id (empty when there is no actor), action, resource type, resource id
 * (empty when null), metadata and the hex-encoded previous hash. Hashing uses
 * {@code MessageDigest} with {@code "SHA-256"}; no custom cryptography is
 * implemented anywhere.
 *
 * <p><b>Concurrency.</b> Chain writers are serialized by a JVM-level
 * {@link ReentrantLock}: the lock is held while the current tip is read, the
 * hash is computed and the record is committed. Every write runs in its own
 * transaction ({@code PROPAGATION_REQUIRES_NEW}), so the next writer can only
 * observe a fully committed predecessor - concurrent calls can therefore
 * neither fork nor duplicate a chain link. This is the simplest mechanism
 * compatible with the current architecture (a single Spring Boot instance and
 * either MySQL or H2, no schema change). If the backend is ever deployed as
 * multiple instances, the JVM lock must be replaced by a database-level
 * equivalent (e.g. {@code SELECT ... FOR UPDATE} on a dedicated lock row)
 * before those instances may write audit records.
 *
 * <p><b>Tamper-resistance limitation.</b> The chain makes undetected
 * single-record edits fail verification, but it is NOT tamper-proof against a
 * database administrator (or any attacker with full write access to the
 * database) who rewrites every subsequent record and recomputes the hashes:
 * the rewritten chain validates cleanly. Defending against that threat model
 * requires anchoring checkpoints of the chain outside the database (e.g.
 * periodically signed and published digests), which is out of scope here.
 *
 * <p>Metadata must only ever contain safe values: never plaintext secrets,
 * encrypted secret contents, passwords, private keys, access tokens or
 * cryptographic key material (AGENTS.md section 12).
 */
@Service
public class AuditLogService {

    /** First link of the chain: 32 zero bytes (SHA-256 output size). */
    private static final byte[] GENESIS_HASH = new byte[32];

    /** Separator of canonical fields; never occurs in any canonical field. */
    private static final String CANONICAL_SEPARATOR = "\u0000";

    private final AuditLogRepository auditLogRepository;
    private final TransactionTemplate transactionTemplate;

    /**
     * Serializes all chain writes inside this JVM. Held across
     * read-tip -> hash -> commit so no two writers can ever derive a link
     * from the same predecessor.
     */
    private final ReentrantLock chainLock = new ReentrantLock();

    public AuditLogService(AuditLogRepository auditLogRepository,
                           PlatformTransactionManager transactionManager) {
        this.auditLogRepository = auditLogRepository;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        // Own transaction per record: it commits before the lock is released,
        // regardless of any transaction the caller may already have open.
        this.transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * Appends one record to the hash chain and returns the persisted entity.
     * Chain generation (tip lookup, canonical form, SHA-256) happens here and
     * never in calling controllers. {@code metadata} must already be limited
     * to safe values; plaintext secrets, ciphertext and key material must
     * never be passed in.
     */
    public AuditLog record(User actor, String action, String resourceType, String resourceId, String metadata) {
        if (action == null || action.isBlank()) {
            throw new InvalidOperationRequestException("audit action must not be blank");
        }
        if (resourceType == null || resourceType.isBlank()) {
            throw new InvalidOperationRequestException("audit resourceType must not be blank");
        }
        if (metadata == null) {
            throw new InvalidOperationRequestException("audit metadata must not be null");
        }
        chainLock.lock();
        try {
            return transactionTemplate.execute(status -> {
                AuditLog tip = findChainTip();
                byte[] previousHash = tip == null ? GENESIS_HASH.clone() : tip.getRecordHash();
                AuditLog entry = new AuditLog(actor, action, resourceType, resourceId, metadata,
                        previousHash, GENESIS_HASH.clone());
                entry.sealRecordHash(sha256(canonicalForm(entry)));
                return auditLogRepository.save(entry);
            });
        } finally {
            chainLock.unlock();
        }
    }

    /**
     * Recomputes every record's hash and checks that all records form a single
     * unbroken chain starting at the genesis value. Returns {@code false} on
     * any modification, fork or orphaned record; an empty chain is valid.
     * Detection only - deciding what to do about a broken chain (e.g. raising
     * a security alert) is left to the caller.
     */
    public boolean verifyChain() {
        chainLock.lock();
        try {
            return Boolean.TRUE.equals(transactionTemplate.execute(status -> {
                List<AuditLog> all = auditLogRepository.findAll();
                Map<String, AuditLog> byPreviousHash = new HashMap<>();
                for (AuditLog entry : all) {
                    if (byPreviousHash.putIfAbsent(HexFormat.of().formatHex(entry.getPreviousHash()), entry) != null) {
                        return false; // two records claim the same predecessor: fork
                    }
                }
                byte[] current = GENESIS_HASH;
                Set<UUID> visited = new HashSet<>();
                while (true) {
                    AuditLog next = byPreviousHash.get(HexFormat.of().formatHex(current));
                    if (next == null) {
                        break;
                    }
                    if (!visited.add(next.getId())) {
                        return false; // crafted cycle instead of a linear chain
                    }
                    if (!Arrays.equals(sha256(canonicalForm(next)), next.getRecordHash())) {
                        return false; // stored content no longer matches its hash
                    }
                    current = next.getRecordHash();
                }
                return visited.size() == all.size(); // every record reachable from genesis
            }));
        } finally {
            chainLock.unlock();
        }
    }

    /**
     * Walks the chain from the genesis value to its newest record. Only called
     * while holding the chain lock. Fails loudly if a fork or a cycle exists -
     * both mean records were written outside this service.
     */
    private AuditLog findChainTip() {
        Map<String, AuditLog> byPreviousHash = new HashMap<>();
        for (AuditLog entry : auditLogRepository.findAll()) {
            if (byPreviousHash.putIfAbsent(HexFormat.of().formatHex(entry.getPreviousHash()), entry) != null) {
                throw new IllegalStateException(
                        "Audit chain fork detected: multiple records share the same previous hash");
            }
        }
        byte[] current = GENESIS_HASH;
        AuditLog tip = null;
        Set<UUID> visited = new HashSet<>();
        while (true) {
            AuditLog next = byPreviousHash.get(HexFormat.of().formatHex(current));
            if (next == null) {
                return tip;
            }
            if (!visited.add(next.getId())) {
                throw new IllegalStateException("Audit chain cycle detected");
            }
            tip = next;
            current = next.getRecordHash();
        }
    }

    /**
     * Deterministic canonical representation of a record: all identity and
     * content fields joined with a NUL separator (no canonical field can ever
     * contain one), plus the hex-encoded previous hash. This exact string is
     * both hashed by {@link #record} and re-hashed by {@link #verifyChain},
     * so any change to a covered field changes the expected hash.
     */
    private static String canonicalForm(AuditLog entry) {
        return String.join(CANONICAL_SEPARATOR,
                entry.getId().toString(),
                entry.getTimestamp().toString(),
                entry.getActor() == null ? "" : entry.getActor().getId().toString(),
                entry.getAction(),
                entry.getResourceType(),
                entry.getResourceId() == null ? "" : entry.getResourceId(),
                entry.getMetadata(),
                HexFormat.of().formatHex(entry.getPreviousHash()));
    }

    private static byte[] sha256(String canonical) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available in this JVM", e);
        }
    }
}
