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

    @Transactional
    public Decision checkAndTouch(String sessionId, String userSubject) {

        // Bez sid i sub ne možemo pouzdano pratiti sesiju.
        if (sessionId == null || sessionId.isBlank()
                || userSubject == null || userSubject.isBlank()) {
            return Decision.MAXIMUM_DURATION;
        }

        LocalDateTime now = LocalDateTime.now();

        SecurityPolicy policy = policyService.getCurrent();

        /*
         * Kreiraj zapis samo ako ne postoji.
         * INSERT IGNORE ne resetuje postojeći started_at.
         */
        jdbcTemplate.update("""
                INSERT IGNORE INTO app_sessions
                    (session_id, user_subject, started_at, last_activity_at)
                VALUES (?, ?, ?, ?)
                """,
                sessionId,
                userSubject,
                Timestamp.valueOf(now),
                Timestamp.valueOf(now)
        );

        /*
         * Zaključavamo zapis dok provjeravamo i ažuriramo aktivnost.
         * Time sprečavamo da paralelni zahtjevi obnove istekli zapis.
         */
        SessionRow session = jdbcTemplate.queryForObject("""
                SELECT user_subject, started_at, last_activity_at
                FROM app_sessions
                WHERE session_id = ?
                FOR UPDATE
                """,
                (rs, rowNum) -> new SessionRow(
                        rs.getString("user_subject"),
                        rs.getTimestamp("started_at").toLocalDateTime(),
                        rs.getTimestamp("last_activity_at").toLocalDateTime()
                ),
                sessionId
        );

        if (session == null || !userSubject.equals(session.userSubject())) {
            return Decision.MAXIMUM_DURATION;
        }

        // 1. Provjera maksimalnog trajanja sesije.
        LocalDateTime maxSessionEnd = session.startedAt()
                .plusMinutes(policy.getMaxSessionDurationMinutes());

        if (!now.isBefore(maxSessionEnd)) {
            jdbcTemplate.update(
                    "DELETE FROM app_sessions WHERE session_id = ?",
                    sessionId
            );

            return Decision.MAXIMUM_DURATION;
        }

        // 2. Provjera neaktivnosti.
        LocalDateTime inactivityEnd = session.lastActivityAt()
                .plusMinutes(policy.getSessionDurationMinutes());

        if (!now.isBefore(inactivityEnd)) {
            jdbcTemplate.update(
                    "DELETE FROM app_sessions WHERE session_id = ?",
                    sessionId
            );

            return Decision.INACTIVITY_TIMEOUT;
        }

        // 3. Sesija je validna — ažuriraj posljednju aktivnost.
        jdbcTemplate.update("""
                UPDATE app_sessions
                SET last_activity_at = ?
                WHERE session_id = ?
                """,
                Timestamp.valueOf(now),
                sessionId
        );

        return Decision.ALLOWED;
    }

    @Transactional
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
            LocalDateTime lastActivityAt
    ) {
    }
}