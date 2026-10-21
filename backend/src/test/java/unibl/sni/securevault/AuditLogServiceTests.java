package unibl.sni.securevault;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import unibl.sni.securevault.entity.AuditLog;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.repository.AuditLogRepository;
import unibl.sni.securevault.repository.UserRepository;
import unibl.sni.securevault.service.AuditLogService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the SHA-256 audit hash chain: genesis linkage and ordering,
 * tamper detection, input validation and concurrent writers. Runs against the
 * in-memory H2 test database. Each test starts from an empty audit table so
 * its chain always begins at the genesis value; no audit rows are ever
 * written outside {@link AuditLogService}, so the committed chain stays
 * intact for every other test class that verifies it.
 */
@SpringBootTest
@ActiveProfiles("test")
class AuditLogServiceTests {

    @Autowired private AuditLogService auditLogService;
    @Autowired private AuditLogRepository auditLogRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    private User actor;

    @BeforeEach
    void startFromEmptyChain() {
        auditLogRepository.deleteAll();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        actor = userRepository.save(new User("kc-audit-" + suffix, "audit-" + suffix,
                Role.DEVELOPER, UserStatus.ACTIVE));
    }

    @Test
    void recordsChainFromGenesisInInsertionOrder() {
        AuditLog first = auditLogService.record(actor, "CHAIN_A", "SECRET", null, "{}");
        AuditLog second = auditLogService.record(actor, "CHAIN_B", "SECRET", null, "{}");
        AuditLog third = auditLogService.record(actor, "CHAIN_C", "SECRET", null, "{}");

        assertArrayEquals(new byte[32], first.getPreviousHash(),
                "the first record must chain from the genesis value");
        assertArrayEquals(first.getRecordHash(), second.getPreviousHash(),
                "each record must reference its predecessor's hash");
        assertArrayEquals(second.getRecordHash(), third.getPreviousHash(),
                "each record must reference its predecessor's hash");
        assertEquals(32, first.getRecordHash().length, "record hashes are raw SHA-256 bytes");
        assertFalse(second.getTimestamp().isBefore(first.getTimestamp()),
                "timestamps must not go backwards along the chain");
        assertFalse(third.getTimestamp().isBefore(second.getTimestamp()),
                "timestamps must not go backwards along the chain");

        assertEquals(actor.getId(), first.getActor().getId(), "the actor must be recorded");
        assertEquals("CHAIN_A", first.getAction());
        assertEquals("SECRET", first.getResourceType());
        assertEquals("{}", first.getMetadata());
        assertNotNull(first.getTimestamp());

        assertTrue(auditLogService.verifyChain(), "the stored chain must verify");
    }

    @Test
    void modifyingAStoredRecordBreaksVerification() {
        auditLogService.record(actor, "TAMPER_A", "SECRET", null, "{}");
        AuditLog middle = auditLogService.record(actor, "TAMPER_B", "SECRET", null, "{}");
        auditLogService.record(actor, "TAMPER_C", "SECRET", null, "{}");
        assertTrue(auditLogService.verifyChain(), "an untouched chain must verify");

        jdbcTemplate.update("UPDATE audit_logs SET metadata = ? WHERE id = ?",
                "{\"modified\":true}", middle.getId().toString());
        assertFalse(auditLogService.verifyChain(), "any modification of a record must be detected");

        jdbcTemplate.update("UPDATE audit_logs SET metadata = ? WHERE id = ?",
                "{}", middle.getId().toString());
        assertTrue(auditLogService.verifyChain(),
                "restoring the exact original content must make the chain valid again");
    }

    @Test
    void concurrentRecordCallsProduceOneUnbrokenChain() throws Exception {
        int threads = 4;
        int perThread = 5;
        List<Throwable> failures = Collections.synchronizedList(new ArrayList<>());
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        for (int t = 0; t < threads; t++) {
            int threadNo = t;
            pool.execute(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        auditLogService.record(actor, "CONCURRENT_" + threadNo, "SECRET", null, "{}");
                    }
                } catch (Throwable e) {
                    failures.add(e);
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "worker threads must finish in time");
        assertTrue(failures.isEmpty(), () -> "unexpected failures: " + failures);
        assertEquals(threads * perThread, auditLogRepository.count(),
                "every concurrent record must be stored exactly once");
        assertTrue(auditLogService.verifyChain(),
                "concurrent writes must neither fork nor break the chain");
    }

    @Test
    void invalidInputIsRejectedWithoutTouchingTheChain() {
        long before = auditLogRepository.count();
        assertThrows(InvalidOperationRequestException.class,
                () -> auditLogService.record(actor, " ", "SECRET", null, "{}"));
        assertThrows(InvalidOperationRequestException.class,
                () -> auditLogService.record(actor, "VALID_ACTION", " ", null, "{}"));
        assertThrows(InvalidOperationRequestException.class,
                () -> auditLogService.record(actor, "VALID_ACTION", "SECRET", null, null));
        assertEquals(before, auditLogRepository.count(), "rejected input must not append records");
        assertTrue(auditLogService.verifyChain());
    }
}
