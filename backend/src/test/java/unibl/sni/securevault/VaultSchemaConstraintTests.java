package unibl.sni.securevault;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.AuditLog;
import unibl.sni.securevault.entity.HoneypotSecret;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.Secret;
import unibl.sni.securevault.entity.SecretShare;
import unibl.sni.securevault.entity.SecurityEvent;
import unibl.sni.securevault.entity.SecurityPolicy;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserKey;
import unibl.sni.securevault.entity.UserStatus;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the Flyway schema (V2 on H2) accepts valid data for every
 * entity and enforces the important constraints: unique share per recipient,
 * one key record per user, NOT NULL columns and policy CHECK constraints.
 * Runs only against the in-memory H2 test database.
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class VaultSchemaConstraintTests {

    @PersistenceContext
    private EntityManager em;

    private User user(String keycloakId, String username) {
        User u = new User(keycloakId, username, Role.DEVELOPER, UserStatus.ACTIVE);
        em.persist(u);
        return u;
    }

    private Secret secret(User owner) {
        Secret s = new Secret(owner, "api-key", null, new byte[16], new byte[32],
                new byte[12], new byte[12], "AES-256-GCM");
        em.persist(s);
        return s;
    }

    private String allMessages(Throwable t) {
        StringBuilder sb = new StringBuilder();
        while (t != null) {
            sb.append(t.getMessage()).append(" | ");
            t = t.getCause();
        }
        return sb.toString().toLowerCase();
    }

    @Test
    void fullSchemaRoundTripPersists() {
        User owner = user("kc-1", "alice");
        User recipient = user("kc-2", "bob");
        em.persist(new UserKey(owner, new byte[10], new byte[16], new byte[12],
                "PBKDF2-HMAC-SHA-256", "{\"iterations\":600000}"));
        Secret s = secret(owner);
        em.persist(new SecretShare(s, recipient, new byte[32]));
        em.persist(new SecurityPolicy(12, 90, 60));
        em.persist(new AuditLog(owner, "SECRET_CREATE", "SECRET", s.getId().toString(),
                "{}", new byte[32], new byte[32]));
        em.persist(new HoneypotSecret(owner, "decoy", new byte[8], null, "{}"));
        em.persist(new SecurityEvent(recipient, "FAILED_LOGIN", "127.0.0.1", "{}"));
        em.flush();
        em.clear();

        User found = em.find(User.class, owner.getId());
        assertNotNull(found);
        assertEquals("alice", found.getUsername());
        assertNotNull(em.find(Secret.class, s.getId()), "secret must be readable after flush");
    }

    @Test
    void duplicateShareForSameRecipientIsRejected() {
        User owner = user("kc-3", "carol");
        User recipient = user("kc-4", "dave");
        Secret s = secret(owner);
        em.persist(new SecretShare(s, recipient, new byte[32]));
        em.flush();

        em.persist(new SecretShare(s, recipient, new byte[32]));
        Exception ex = assertThrows(Exception.class, () -> em.flush());
        String messages = allMessages(ex);
        assertTrue(messages.contains("uq_secret_shares_secret_recipient"),
                "expected unique-constraint violation, got: " + messages);
    }

    @Test
    void secondUserKeyForSameUserIsRejected() {
        User u = user("kc-5", "erin");
        em.persist(new UserKey(u, new byte[10], new byte[16], new byte[12],
                "PBKDF2-HMAC-SHA-256", "{}"));
        em.flush();

        em.persist(new UserKey(u, new byte[10], new byte[16], new byte[12],
                "PBKDF2-HMAC-SHA-256", "{}"));
        Exception ex = assertThrows(Exception.class, () -> em.flush());
        String messages = allMessages(ex);
        assertTrue(messages.contains("uq_user_keys_user_id"),
                "expected unique-constraint violation, got: " + messages);
    }

    @Test
    void nullUsernameIsRejected() {
        em.persist(new User("kc-6", null, Role.ADMIN, UserStatus.ACTIVE));
        Exception ex = assertThrows(Exception.class, () -> em.flush());
        String messages = allMessages(ex);
        assertTrue(messages.contains("username") && messages.contains("null"),
                "expected NOT NULL violation on username, got: " + messages);
    }

    @Test
    void policyBelowMinimumLengthIsRejected() {
        em.persist(new SecurityPolicy(4, 30, 60));
        Exception ex = assertThrows(Exception.class, () -> em.flush());
        String messages = allMessages(ex);
        assertTrue(messages.contains("chk_security_policies_min_length"),
                "expected CHECK violation, got: " + messages);
    }
}
