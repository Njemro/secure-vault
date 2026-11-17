package unibl.sni.securevault.controller;

import unibl.sni.securevault.dto.SecurityIncidentResponse;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

@RestController
@RequestMapping("/api/admin/security-incidents")
public class AdminSecurityIncidentController {

    private final JdbcTemplate jdbcTemplate;
    private final UserRepository userRepository;

    public AdminSecurityIncidentController(
            JdbcTemplate jdbcTemplate,
            UserRepository userRepository
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.userRepository = userRepository;
    }

    @GetMapping
    public List<SecurityIncidentResponse> list(
            @AuthenticationPrincipal Jwt jwt
    ) {
        requireAdmin(jwt);

        return jdbcTemplate.query(
                """
                SELECT
                    e.id,
                    e.event_time,
                    e.event_type,
                    u.username,
                    e.source_ip,
                    e.metadata
                FROM security_events e
                LEFT JOIN users u ON u.id = e.user_id
                ORDER BY e.event_time DESC
                LIMIT 100
                """,
                (rs, rowNum) -> mapIncident(rs)
        );
    }

    private SecurityIncidentResponse mapIncident(ResultSet rs)
            throws SQLException {
        return new SecurityIncidentResponse(
                rs.getString("id"),
                rs.getTimestamp("event_time").toLocalDateTime(),
                rs.getString("event_type"),
                rs.getString("username"),
                rs.getString("source_ip"),
                rs.getString("metadata")
        );
    }

    private void requireAdmin(Jwt jwt) {
        User user = userRepository.findByKeycloakId(jwt.getSubject())
                .filter(u -> "ACTIVE".equals(u.getStatus().name()))
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.FORBIDDEN,
                                "Account is not active"
                        )
                );

        if (!"ADMIN".equals(user.getRole().name())) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "Administrator access required"
            );
        }
    }
}
