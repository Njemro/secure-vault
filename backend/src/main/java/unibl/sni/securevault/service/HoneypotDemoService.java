
package unibl.sni.securevault.service;

import unibl.sni.securevault.entity.HoneypotDemoState;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.repository.HoneypotDemoStateRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Service
public class HoneypotDemoService {

    private final HoneypotDemoStateRepository stateRepository;
    private final JdbcTemplate jdbcTemplate;
    private final HoneypotDetectionService detectionService;

    public HoneypotDemoService(
            HoneypotDemoStateRepository stateRepository,
            JdbcTemplate jdbcTemplate,
            HoneypotDetectionService detectionService
    ) {
        this.stateRepository = stateRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.detectionService = detectionService;
    }

    @Transactional(readOnly = true)
    public HoneypotDemoState getState() {
        return stateRepository.findById(1)
                .orElseThrow(() ->
                        new IllegalStateException(
                                "Honeypot demo state is missing"
                        ));
    }

    @Transactional
    public void enable(User admin, int durationMinutes) {
        if (durationMinutes < 1 || durationMinutes > 30) {
            throw new IllegalArgumentException(
                    "Demo duration must be between 1 and 30 minutes"
            );
        }

        HoneypotDemoState state = stateRepository.findById(1)
                .orElseThrow(() ->
                        new IllegalStateException(
                                "Honeypot demo state is missing"
                        ));

        state.enable(admin, durationMinutes);
        stateRepository.save(state);
    }

    @Transactional
    public void disable() {
        HoneypotDemoState state = stateRepository.findById(1)
                .orElseThrow(() ->
                        new IllegalStateException(
                                "Honeypot demo state is missing"
                        ));

        state.disable();
        stateRepository.save(state);
    }

    public String runVulnerableSearch(
            User currentUser,
            String searchTerm,
            String sourceIp
    ) {
        HoneypotDemoState state = getState();

        if (!state.isEnabled()) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "HONEYPOT_DEMO_DISABLED"
            );
        }

        if (searchTerm == null || searchTerm.length() > 120) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Search term must contain at most 120 characters"
            );
        }

        // INTENTIONALLY VULNERABLE:
        // This query is isolated to honeypot_secrets.
        // Never reuse this pattern for application data.
        String sql =
                "SELECT id, owner_id " +
                "FROM honeypot_secrets " +
                "WHERE owner_id = '" +
                currentUser.getId() +
                "' AND name = '" +
                searchTerm +
                "' LIMIT 5";

        
        String honeypotId = jdbcTemplate.query(
                sql,
                resultSet -> resultSet.next() ? resultSet.getString("id") : null
        );

        if (honeypotId != null) {
            detectionService.detectAndFreeze(
                    currentUser,
                    sourceIp,
                    honeypotId
            );

            // Ne vraćamo podatke mamca niti potvrđujemo detekciju.
            return "Request processed.";
        }

        return "No matching records.";

    }
}
