
package unibl.sni.securevault.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import unibl.sni.securevault.entity.SecurityPolicy;

import java.sql.Timestamp;
import java.time.LocalDateTime;

@Service
public class SessionEnforcementService {

    public enum Decision {
        ALLOWED,
        INACTIVITY_TIMEOUT,
        MAXIMUM_DURATION
    }

    private final JdbcTemplate jdbcTemplate;
    private final SecurityPolicyService policyService;

    public SessionEnforcementService(
            JdbcTemplate jdbcTemplate,
            SecurityPolicyService policyService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.policyService = policyService;
    }

    public Decision checkAndTouch(String sessionId, String userSubject) {

        if (sessionId == null || sessionId.isBlank()
                || userSubject == null || userSubject.isBlank()) {
            return Decision.MAXIMUM_DURATION;
        }

        SecurityPolicy policy = policyService.getCurrent();

        int maxDuration = policy.getMaxSessionDurationMinutes();
        int inactivityDuration = policy.getSessionDurationMinutes();

        /*
         * Kreiraj sesiju samo ako ne postoji.
         * Postojeći started_at se nikada ne resetuje.
         */
        jdbcTemplate.update("""
                INSERT IGNORE INTO app_sessions
                    (session_id, user_subject, started_at, last_activity_at)
                VALUES (?, ?, CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6))
                """,
                sessionId,
                userSubject
        );

        /*
         * Atomska provjera i ažuriranje.
         *
         * Sesija se ažurira samo ako:
         * 1. Pripada trenutnom korisniku.
         * 2. Nije prekoračeno maksimalno trajanje.
         * 3. Nije prekoračeno vrijeme neaktivnosti.
         *
         * Nema SELECT FOR UPDATE.
         */
        int updated = jdbcTemplate.update("""
                UPDATE app_sessions
                SET last_activity_at = CURRENT_TIMESTAMP(6)
                WHERE session_id = ?
                  AND user_subject = ?
                  AND TIMESTAMPADD(
                        MINUTE, ?, started_at
                      ) > CURRENT_TIMESTAMP(6)
                  AND TIMESTAMPADD(
                        MINUTE, ?, last_activity_at
                      ) > CURRENT_TIMESTAMP(6)
                """,
                sessionId,
                userSubject,
                maxDuration,
                inactivityDuration
        );

        if (updated > 0) {
            return Decision.ALLOWED;
        }

        /*
         * Ako UPDATE nije izvršen, utvrdi razlog.
         * Ovo je običan SELECT bez zaključavanja reda.
         */
        SessionRow session = jdbcTemplate.query("""
                SELECT
                    user_subject,
                    started_at,
                    last_activity_at,
                    CURRENT_TIMESTAMP(6) AS db_now
                FROM app_sessions
                WHERE session_id = ?
                """,
                rs -> {
                    if (!rs.next()) {
                        return null;
                    }

                    return new SessionRow(
                            rs.getString("user_subject"),
                            rs.getTimestamp("started_at").toLocalDateTime(),
                            rs.getTimestamp("last_activity_at").toLocalDateTime(),
                            rs.getTimestamp("db_now").toLocalDateTime()
                    );
                },
                sessionId
        );

        if (session == null || !userSubject.equals(session.userSubject())) {
            return Decision.MAXIMUM_DURATION;
        }

        LocalDateTime maxSessionEnd = session.startedAt()
                .plusMinutes(maxDuration);

        if (!session.dbNow().isBefore(maxSessionEnd)) {
            return Decision.MAXIMUM_DURATION;
        }

        LocalDateTime inactivityEnd = session.lastActivityAt()
                .plusMinutes(inactivityDuration);

        if (!session.dbNow().isBefore(inactivityEnd)) {
            return Decision.INACTIVITY_TIMEOUT;
        }

        /*
         * Ako je sesija i dalje validna, a UPDATE nije prijavio
         * promjenu (npr. dva veoma bliska zahtjeva), dozvoli zahtjev.
         */
        return Decision.ALLOWED;
    }

    public void removeSession(String sessionId) {
        if (sessionId != null && !sessionId.isBlank()) {
            jdbcTemplate.update(
                    "DELETE FROM app_sessions WHERE session_id = ?",
                    sessionId
            );
        }
    }

    private record SessionRow(
            String userSubject,
            LocalDateTime startedAt,
            LocalDateTime lastActivityAt,
            LocalDateTime dbNow
    ) {
    }
}