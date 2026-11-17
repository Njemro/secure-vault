package unibl.sni.securevault.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.repository.UserRepository;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class HoneypotDetectionService {

    private static final Logger log =
            LoggerFactory.getLogger(HoneypotDetectionService.class);

    private final UserRepository userRepository;
    private final JdbcTemplate jdbcTemplate;
    private final AuditLogService auditLogService;
    private final KeycloakAdminService keycloakAdminService;

    public HoneypotDetectionService(
            UserRepository userRepository,
            JdbcTemplate jdbcTemplate,
            AuditLogService auditLogService,
            KeycloakAdminService keycloakAdminService) {

        this.userRepository = userRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.auditLogService = auditLogService;
        this.keycloakAdminService = keycloakAdminService;
    }

    @Transactional
    public void detectAndFreeze(User user, String sourceIp, String honeypotId) {

        if (user == null || user.getId() == null) {
            throw new IllegalArgumentException("A valid user is required.");
        }

        User target = userRepository.findById(user.getId())
                .orElseThrow(() ->
                        new IllegalStateException("User not found."));

        // Ne mijenjamo već suspendovan ili onemogućen nalog.
        if (target.getStatus() != UserStatus.ACTIVE) {
            return;
        }

        target.changeStatus(UserStatus.SUSPENDED);
        userRepository.save(target);

        UUID eventId = UUID.randomUUID();
        LocalDateTime eventTime = LocalDateTime.now();

        // Bilježimo samo identifikator mamca i razlog; nikada sadržaj mamca.
        String safeHoneytokenId = honeypotId == null ? "unknown" : honeypotId;
        String metadata =
                "{\"reason\":\"HONEYPOT_ACCESS\","
                + "\"action\":\"ACCOUNT_SUSPENDED\","
                + "\"honeypotId\":\"" + safeHoneytokenId + "\"}";

        jdbcTemplate.update(
                """
                INSERT INTO security_events
                    (id, event_time, user_id, event_type, source_ip, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                eventId.toString(),
                Timestamp.valueOf(eventTime),
                target.getId().toString(),
                "HONEYPOT_ACCESS",
                sourceIp,
                metadata
        );

        String keycloakId = target.getKeycloakId();
        UUID userId = target.getId();

        // Spoljne operacije izvršavamo tek nakon uspješnog DB commit-a.
        TransactionSynchronizationManager.registerSynchronization(
                new TransactionSynchronization() {
                    @Override
                    public void afterCommit() {

                        try {
                            auditLogService.record(
                                    null,
                                    "HONEYPOT_ACCESS_DETECTED",
                                    "USER",
                                    userId.toString(),
                                    metadata
                            );
                        } catch (RuntimeException e) {
                            log.error(
                                    "Failed to write honeypot audit log for user {}",
                                    userId,
                                    e
                            );
                        }

                        try {
                            keycloakAdminService.setUserEnabled(keycloakId, false);
                        } catch (RuntimeException e) {
                            // Lokalni status SUSPENDED i dalje blokira svaki naredni API poziv.
                            log.error(
                                    "Failed to disable Keycloak account after honeypot detection. User: {}",
                                    userId,
                                    e
                            );
                        }

                        // Pokušaj odjave je nezavisan od pokušaja disable operacije.
                        try {
                            keycloakAdminService.logoutUser(keycloakId);
                        } catch (RuntimeException e) {
                            log.error(
                                    "Failed to revoke Keycloak sessions after honeypot detection. User: {}",
                                    userId,
                                    e
                            );
                        }
                    }
                }
        );
    }
}