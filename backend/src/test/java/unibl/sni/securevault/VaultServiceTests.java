package unibl.sni.securevault;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import unibl.sni.securevault.entity.AuditLog;
import unibl.sni.securevault.entity.HoneypotSecret;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.Secret;
import unibl.sni.securevault.entity.SecretShare;
import unibl.sni.securevault.entity.SecurityEvent;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserKey;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.repository.AuditLogRepository;
import unibl.sni.securevault.repository.SecretRepository;
import unibl.sni.securevault.repository.UserKeyRepository;
import unibl.sni.securevault.repository.UserRepository;
import unibl.sni.securevault.service.AuditLogService;
import unibl.sni.securevault.service.HoneypotSecretService;
import unibl.sni.securevault.service.SecretService;
import unibl.sni.securevault.service.SecretShareService;
import unibl.sni.securevault.service.SecurityEventService;
import unibl.sni.securevault.service.SecurityPolicyService;
import unibl.sni.securevault.service.UserKeyService;
import unibl.sni.securevault.service.UserService;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Focused service-layer tests: owner scoping, share validation, atomicity of
 * multi-recipient sharing, and the minimal persist operations. Runs against
 * in-memory H2 only; writes are not rolled back, so each test uses distinct
 * "svc-" prefixed data to stay isolated.
 */
@SpringBootTest
@ActiveProfiles("test")
class VaultServiceTests {

    @Autowired private UserService userService;
    @Autowired private UserKeyService userKeyService;
    @Autowired private SecretService secretService;
    @Autowired private SecretShareService secretShareService;
    @Autowired private SecurityPolicyService securityPolicyService;
    @Autowired private AuditLogService auditLogService;
    @Autowired private HoneypotSecretService honeypotSecretService;
    @Autowired private SecurityEventService securityEventService;
    @Autowired private UserRepository userRepository;
    @Autowired private UserKeyRepository userKeyRepository;
    @Autowired private SecretRepository secretRepository;
    @Autowired private AuditLogRepository auditLogRepository;

    private User newUser(String suffix) {
        return userRepository.save(new User("kc-svc-" + suffix, "svc-" + suffix,
                Role.DEVELOPER, UserStatus.ACTIVE));
    }

    private void addKey(User user) {
        userKeyRepository.save(new UserKey(user, new byte[8], new byte[16], new byte[12],
                "PBKDF2-HMAC-SHA-256", "{}"));
    }

    private Secret newSecret(User owner, String name) {
        return secretService.createSecret(owner.getId(), name, null,
                new byte[16], new byte[16], new byte[12], new byte[12], "AES-256-GCM");
    }

    private static String allMessages(Throwable t) {
        StringBuilder sb = new StringBuilder();
        while (t != null) {
            sb.append(t.getMessage()).append(" | ");
            t = t.getCause();
        }
        return sb.toString().toLowerCase();
    }

    @Test
    void userAndKeyLookups() {
        User u = newUser("lookup-1");

        assertTrue(userService.findByUsername("svc-lookup-1").isPresent());
        assertTrue(userService.findByUsername("svc-does-not-exist").isEmpty());
        assertEquals(u.getId(), userService.findByKeycloakId("kc-svc-lookup-1").get().getId());
        assertEquals(u.getId(), userService.getById(u.getId()).getId());

        assertThrows(ResourceNotFoundException.class, () -> userService.getById(UUID.randomUUID()));
        assertThrows(InvalidOperationRequestException.class, () -> userService.findByUsername(" "));
        assertThrows(InvalidOperationRequestException.class, () -> userService.findByKeycloakId(null));
        assertThrows(InvalidOperationRequestException.class, () -> userKeyService.findByUserId(null));

        assertTrue(userKeyService.findByUserId(u.getId()).isEmpty());
        addKey(u);
        assertTrue(userKeyService.findByUserId(u.getId()).isPresent());
        assertTrue(userKeyService.findByUserId(UUID.randomUUID()).isEmpty());
    }

    @Test
    void secretReadIsScopedToOwner() {
        User owner = newUser("own-1");
        User other = newUser("own-2");
        Secret secret = newSecret(owner, "svc-secret-own");

        assertEquals("svc-secret-own",
                secretService.getOwnedSecret(secret.getId(), owner.getId()).getName());
        assertThrows(InvalidOperationRequestException.class,
                () -> secretService.getOwnedSecret(secret.getId(), other.getId()));
        assertThrows(ResourceNotFoundException.class,
                () -> secretService.getOwnedSecret(UUID.randomUUID(), owner.getId()));

        assertThrows(ResourceNotFoundException.class, () -> secretService.createSecret(
                UUID.randomUUID(), "x", null, new byte[4], new byte[4], new byte[12], new byte[12],
                "AES-256-GCM"));
        assertThrows(InvalidOperationRequestException.class, () -> secretService.createSecret(
                owner.getId(), " ", null, new byte[4], new byte[4], new byte[12], new byte[12],
                "AES-256-GCM"));
        assertThrows(InvalidOperationRequestException.class, () -> secretService.createSecret(
                owner.getId(), "x", null, new byte[0], new byte[4], new byte[12], new byte[12],
                "AES-256-GCM"));

        assertEquals(1, secretService.findByOwnerId(owner.getId()).size());
    }

    @Test
    void sharingRequiresOwnerAndValidRecipients() {
        User owner = newUser("shr-1");
        User other = newUser("shr-2");
        User withoutKey = newUser("shr-3");
        Secret secret = newSecret(owner, "svc-secret-shr");
        UUID secretId = secret.getId();
        UUID ownerId = owner.getId();

        // Not the owner.
        assertThrows(InvalidOperationRequestException.class, () -> secretShareService.createShares(
                secretId, other.getId(), List.of(other.getId()), List.of(new byte[16])));
        // Unknown secret.
        assertThrows(ResourceNotFoundException.class, () -> secretShareService.createShares(
                UUID.randomUUID(), ownerId, List.of(other.getId()), List.of(new byte[16])));
        // Unknown recipient.
        assertThrows(ResourceNotFoundException.class, () -> secretShareService.createShares(
                secretId, ownerId, List.of(UUID.randomUUID()), List.of(new byte[16])));
        // Recipient exists but has no UserKey record.
        assertThrows(ResourceNotFoundException.class, () -> secretShareService.createShares(
                secretId, ownerId, List.of(withoutKey.getId()), List.of(new byte[16])));
        // Sharing with the owner is rejected.
        assertThrows(InvalidOperationRequestException.class, () -> secretShareService.createShares(
                secretId, ownerId, List.of(ownerId), List.of(new byte[16])));
        // Recipient/DEK list size mismatch.
        assertThrows(InvalidOperationRequestException.class, () -> secretShareService.createShares(
                secretId, ownerId, List.of(other.getId()), List.of()));

        assertEquals(0, secretShareService.findBySecretId(secretId).size());
    }

    @Test
    void duplicateRecipientsAreRejected() {
        User owner = newUser("dup-1");
        User first = newUser("dup-2");
        User second = newUser("dup-3");
        addKey(first);
        addKey(second);
        Secret secret = newSecret(owner, "svc-secret-dup");

        assertThrows(InvalidOperationRequestException.class, () -> secretShareService.createShares(
                secret.getId(), owner.getId(),
                List.of(first.getId(), second.getId(), first.getId()),
                List.of(new byte[16], new byte[16], new byte[16])));

        assertEquals(0, secretShareService.findBySecretId(secret.getId()).size());
    }

    @Test
    void validMultiRecipientShareLeavesSecretUntouched() {
        User owner = newUser("val-1");
        User first = newUser("val-2");
        User second = newUser("val-3");
        addKey(first);
        addKey(second);
        Secret secret = newSecret(owner, "svc-secret-val");
        byte[] encryptedValueBefore = secret.getEncryptedValue();
        byte[] encryptedDekBefore = secret.getEncryptedDek();

        List<SecretShare> created = secretShareService.createShares(secret.getId(), owner.getId(),
                List.of(first.getId(), second.getId()),
                List.of(new byte[16], new byte[24]));
        assertEquals(2, created.size());
        assertEquals(2, secretShareService.findBySecretId(secret.getId()).size());
        assertEquals(1, secretShareService.findByRecipientId(first.getId()).size());
        assertEquals(1, secretShareService.findByRecipientId(second.getId()).size());

        Secret reloaded = secretRepository.findById(secret.getId()).orElseThrow();
        assertArrayEquals(encryptedValueBefore, reloaded.getEncryptedValue(),
                "sharing must not change the encrypted secret content");
        assertArrayEquals(encryptedDekBefore, reloaded.getEncryptedDek(),
                "sharing must not change the owner's encrypted DEK");
    }

    @Test
    void failedShareLeavesNoPartialShares() {
        User owner = newUser("rlb-1");
        User first = newUser("rlb-2");
        User second = newUser("rlb-3");
        addKey(first);
        addKey(second);
        Secret secret = newSecret(owner, "svc-secret-rlb");
        secretShareService.createShares(secret.getId(), owner.getId(),
                List.of(first.getId()), List.of(new byte[16]));
        assertEquals(1, secretShareService.findBySecretId(secret.getId()).size());

        // The duplicate (first, secret) pair passes service validation but
        // violates the DB unique constraint at commit time; the whole
        // transaction must roll back, including second's would-be share.
        Exception ex = assertThrows(Exception.class, () -> secretShareService.createShares(
                secret.getId(), owner.getId(),
                List.of(first.getId(), second.getId()),
                List.of(new byte[16], new byte[16])));
        assertTrue(allMessages(ex).contains("uq_secret_shares_secret_recipient"),
                "expected unique-constraint failure, got: " + allMessages(ex));
        assertEquals(1, secretShareService.findBySecretId(secret.getId()).size(),
                "no partial share set may remain after a failed operation");
    }

    @Test
    void policyCreateReadAndUpdate() {
        var policy = securityPolicyService.create(10, 30, 60);
        assertEquals(10, securityPolicyService.getById(policy.getId()).getMinMasterPasswordLength());

        var updated = securityPolicyService.update(policy.getId(), 12, 45, 90);
        assertEquals(12, updated.getMinMasterPasswordLength());
        assertEquals(45, updated.getSecretRotationIntervalDays());
        assertEquals(90, updated.getSessionDurationMinutes());
        assertEquals(12, securityPolicyService.getById(policy.getId()).getMinMasterPasswordLength());

        assertThrows(InvalidOperationRequestException.class,
                () -> securityPolicyService.create(4, 30, 60));
        assertThrows(InvalidOperationRequestException.class,
                () -> securityPolicyService.update(policy.getId(), 4, 30, 60));
        assertThrows(ResourceNotFoundException.class,
                () -> securityPolicyService.getById(UUID.randomUUID()));
        assertThrows(ResourceNotFoundException.class,
                () -> securityPolicyService.update(UUID.randomUUID(), 10, 30, 60));
    }

    @Test
    void auditEventAndHoneypotPersistOperations() {
        User u = newUser("min-1");

        AuditLog saved = auditLogService.record(u, "SVC_TEST_ACTION", "USER", u.getId().toString(), "{}");
        assertTrue(auditLogRepository.findById(saved.getId()).isPresent());
        assertThrows(InvalidOperationRequestException.class,
                () -> auditLogService.record(u, " ", "USER", null, "{}"));
        assertThrows(InvalidOperationRequestException.class,
                () -> auditLogService.record(u, "SVC_TEST_ACTION", " ", null, "{}"));
        assertThrows(InvalidOperationRequestException.class,
                () -> auditLogService.record(u, "SVC_TEST_ACTION", "USER", null, null));

        securityEventService.persist(new SecurityEvent(u, "SVC_EVENT_A", "10.9.9.1", "{}"));
        assertThrows(InvalidOperationRequestException.class, () -> securityEventService
                .persist(new SecurityEvent(u, "", null, "{}")));
        securityEventService.persist(new SecurityEvent(u, "SVC_EVENT_B", "10.9.9.2", "{}"));
        List<SecurityEvent> events = securityEventService.findByUserId(u.getId());
        assertEquals(2, events.size());
        for (int i = 1; i < events.size(); i++) {
            assertTrue(!events.get(i - 1).getTimestamp().isBefore(events.get(i).getTimestamp()),
                    "events must be ordered newest first");
        }

        User honeypotOwner = newUser("min-2");
        HoneypotSecret honeypot = honeypotSecretService.persist(
                new HoneypotSecret(honeypotOwner, "svc-decoy", new byte[8], null, "{}"));
        assertEquals("svc-decoy", honeypotSecretService.getById(honeypot.getId()).getName());
        assertThrows(ResourceNotFoundException.class,
                () -> honeypotSecretService.getById(UUID.randomUUID()));
        assertThrows(InvalidOperationRequestException.class, () -> honeypotSecretService
                .persist(new HoneypotSecret(honeypotOwner, " ", new byte[8], null, "{}")));

        // Honeypots never show up in ordinary secret queries.
        newSecret(honeypotOwner, "svc-real-secret");
        List<Secret> ordinary = secretService.findByOwnerId(honeypotOwner.getId());
        assertEquals(1, ordinary.size());
        assertTrue(ordinary.stream().noneMatch(s -> "svc-decoy".equals(s.getName())));
    }

    @Test
    void secretUpdateAndDeleteAreOwnerScoped() {
        User owner = newUser("upd-1");
        User other = newUser("upd-2");
        Secret secret = newSecret(owner, "svc-secret-upd");

        Secret updated = secretService.updateOwnedSecret(secret.getId(), owner.getId(),
                "svc-secret-upd-renamed", "svc-description",
                new byte[20], new byte[24], new byte[12], new byte[12], "AES-256-GCM");
        assertEquals("svc-secret-upd-renamed", updated.getName());
        assertNotNull(updated.getLastRotatedAt(), "replacing ciphertext counts as a rotation");
        assertEquals("svc-secret-upd-renamed",
                secretService.getOwnedSecret(secret.getId(), owner.getId()).getName());

        // Non-owners cannot update or delete; unknown ids are missing resources.
        assertThrows(InvalidOperationRequestException.class, () -> secretService.updateOwnedSecret(
                secret.getId(), other.getId(), "x", null,
                new byte[4], new byte[4], new byte[12], new byte[12], "AES-256-GCM"));
        assertThrows(ResourceNotFoundException.class, () -> secretService.updateOwnedSecret(
                UUID.randomUUID(), owner.getId(), "x", null,
                new byte[4], new byte[4], new byte[12], new byte[12], "AES-256-GCM"));
        assertThrows(InvalidOperationRequestException.class, () -> secretService.updateOwnedSecret(
                secret.getId(), owner.getId(), " ", null,
                new byte[4], new byte[4], new byte[12], new byte[12], "AES-256-GCM"));
        assertThrows(InvalidOperationRequestException.class, () -> secretService.updateOwnedSecret(
                secret.getId(), owner.getId(), "x", null,
                new byte[0], new byte[4], new byte[12], new byte[12], "AES-256-GCM"));

        assertThrows(InvalidOperationRequestException.class,
                () -> secretService.deleteOwnedSecret(secret.getId(), other.getId()));
        secretService.deleteOwnedSecret(secret.getId(), owner.getId());
        assertTrue(secretService.findByOwnerId(owner.getId()).stream()
                .noneMatch(s -> s.getId().equals(secret.getId())), "owned secret must be gone");
        assertThrows(ResourceNotFoundException.class,
                () -> secretService.deleteOwnedSecret(secret.getId(), owner.getId()));
    }
}



