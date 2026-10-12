package unibl.sni.securevault;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.AuditLog;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.Secret;
import unibl.sni.securevault.entity.SecretShare;
import unibl.sni.securevault.entity.SecurityEvent;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserKey;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.repository.AuditLogRepository;
import unibl.sni.securevault.repository.SecretRepository;
import unibl.sni.securevault.repository.SecretShareRepository;
import unibl.sni.securevault.repository.SecurityEventRepository;
import unibl.sni.securevault.repository.UserKeyRepository;
import unibl.sni.securevault.repository.UserRepository;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the derived query methods added in the repository layer against
 * the real Flyway schema on the in-memory H2 test database. All writes are
 * rolled back; MySQL and Redis are never used by tests.
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class VaultRepositoryTests {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserKeyRepository userKeyRepository;
    @Autowired
    private SecretRepository secretRepository;
    @Autowired
    private SecretShareRepository secretShareRepository;
    @Autowired
    private SecurityEventRepository securityEventRepository;
    @Autowired
    private AuditLogRepository auditLogRepository;

    private User user(String keycloakId, String username) {
        return userRepository.save(new User(keycloakId, username, Role.DEVELOPER, UserStatus.ACTIVE));
    }

    private Secret secret(User owner, String name) {
        return secretRepository.save(new Secret(owner, name, null,
                new byte[8], new byte[8], new byte[12], new byte[12], "AES-256-GCM"));
    }

    @Test
    void userAndKeyQueries() {
        User alice = user("kc-a", "alice");
        user("kc-b", "bob");

        assertTrue(userRepository.findByKeycloakId("kc-a").isPresent());
        assertEquals(alice.getId(), userRepository.findByKeycloakId("kc-a").get().getId());
        assertTrue(userRepository.findByUsername("alice").isPresent());
        assertTrue(userRepository.findByUsername("nobody").isEmpty());

        userKeyRepository.save(new UserKey(alice, new byte[8], new byte[16], new byte[12],
                "PBKDF2-HMAC-SHA-256", "{}"));
        assertTrue(userKeyRepository.findByUserId(alice.getId()).isPresent());
        assertTrue(userKeyRepository.findByUserId(java.util.UUID.randomUUID()).isEmpty());
    }

    @Test
    void secretAndShareQueries() {
        User alice = user("kc-c", "carol");
        User bob = user("kc-d", "dave");
        Secret carolSecret = secret(alice, "carol-secret");
        secret(bob, "dave-secret");

        List<Secret> carolsSecrets = secretRepository.findByOwnerId(alice.getId());
        assertEquals(1, carolsSecrets.size());
        assertEquals("carol-secret", carolsSecrets.get(0).getName());

        secretShareRepository.save(new SecretShare(carolSecret, bob, new byte[16]));
        secretShareRepository.save(new SecretShare(carolSecret, alice, new byte[16]));

        assertEquals(1, secretShareRepository.findByRecipientId(bob.getId()).size());
        assertTrue(secretShareRepository.findByRecipientId(java.util.UUID.randomUUID()).isEmpty());
        assertEquals(2, secretShareRepository.findBySecretId(carolSecret.getId()).size());
    }

    @Test
    void eventAndAuditOrdering() {
        User alice = user("kc-e", "erin");
        User bob = user("kc-f", "frank");

        securityEventRepository.save(new SecurityEvent(alice, "FAILED_LOGIN", "10.0.0.1", "{}"));
        securityEventRepository.save(new SecurityEvent(bob, "FAILED_LOGIN", "10.0.0.2", "{}"));
        securityEventRepository.save(new SecurityEvent(alice, "IP_BLOCKED", "10.0.0.3", "{}"));

        List<SecurityEvent> forAlice = securityEventRepository.findByUserIdOrderByTimestampDesc(alice.getId());
        assertEquals(2, forAlice.size());
        for (SecurityEvent e : forAlice) {
            assertEquals(alice.getId(), e.getUser().getId());
        }
        for (int i = 1; i < forAlice.size(); i++) {
            assertFalse(forAlice.get(i - 1).getTimestamp().isBefore(forAlice.get(i).getTimestamp()),
                    "events must be ordered newest first");
        }

        auditLogRepository.save(new AuditLog(alice, "SECRET_CREATE", "SECRET", "{}", "{}",
                new byte[32], new byte[32]));
        auditLogRepository.save(new AuditLog(bob, "LOGIN_SUCCESS", "USER", "{}", "{}",
                new byte[32], new byte[32]));

        List<AuditLog> all = auditLogRepository.findAllByOrderByTimestampAsc();
        assertEquals(2, all.size());
        for (int i = 1; i < all.size(); i++) {
            assertFalse(all.get(i).getTimestamp().isBefore(all.get(i - 1).getTimestamp()),
                    "audit records must be ordered by timestamp ascending");
        }
    }
}
