
package unibl.sni.securevault.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.service.SessionEnforcementService;
import unibl.sni.securevault.service.UserService;
import unibl.sni.securevault.service.OidcUserProvisioningService;

import java.io.IOException;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class SessionEnforcementFilter extends OncePerRequestFilter {

    private final SessionEnforcementService sessionService;
    private final ObjectMapper objectMapper;
    private final UserService userService;
    private final OidcUserProvisioningService oidcUserProvisioningService;
    private static final Logger log =
        LoggerFactory.getLogger(SessionEnforcementFilter.class);

    public SessionEnforcementFilter(
            SessionEnforcementService sessionService,
            ObjectMapper objectMapper,
            UserService userService,
            OidcUserProvisioningService oidcUserProvisioningService
    ) {
        this.sessionService = sessionService;
        this.objectMapper = objectMapper;
        this.userService = userService;
        this.oidcUserProvisioningService = oidcUserProvisioningService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        if (!(authentication instanceof JwtAuthenticationToken jwtAuth)
                || !authentication.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        String sessionId = jwtAuth.getToken().getClaimAsString("sid");
        String userSubject = jwtAuth.getToken().getSubject();

        User account = userService.findByKeycloakId(userSubject).orElse(null);

        // A valid Keycloak OIDC identity may arrive through an external IdP.
        // Provision its local least-privilege profile before enforcing app policies.
        if (account == null) {
            try {
                account = oidcUserProvisioningService.findOrProvision(jwtAuth.getToken());
            } catch (DataIntegrityViolationException concurrentProvisioning) {
                account = userService.findByKeycloakId(userSubject).orElse(null);
                if (account == null) {
                    writeError(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                            "ACCOUNT_PROVISIONING_FAILED",
                            "Account setup is temporarily unavailable. Please retry.");
                    return;
                }
            } catch (RuntimeException exception) {
                log.error("Could not provision local profile for OIDC subject {}", userSubject, exception);
                writeError(
                        response,
                        HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                        "ACCOUNT_PROVISIONING_FAILED",
                        "Account setup is temporarily unavailable. Please retry."
                );
                return;
            }
        }

        if (account.getStatus() != UserStatus.ACTIVE) {

            String code = account.getStatus() == UserStatus.SUSPENDED
                    ? "ACCOUNT_SUSPENDED"
                    : "ACCOUNT_DISABLED";

            String message = account.getStatus() == UserStatus.SUSPENDED
                    ? "Account is suspended."
                    : "Account is disabled.";

            writeError(
                    response,
                    HttpServletResponse.SC_FORBIDDEN,
                    code,
                    message
            );
            return;
        }

        // Provjera da li JWT sadrži trenutno važeću aplikacijsku ulogu.
        Map<String, Object> realmAccess =
                jwtAuth.getToken().getClaim("realm_access");

        Object rawRoles = realmAccess == null
                ? null
                : realmAccess.get("roles");

        boolean tokenAdmin =
                rawRoles instanceof java.util.Collection<?> roles
                        && roles.contains("ADMIN");

        boolean tokenTeamLead =
                rawRoles instanceof java.util.Collection<?> roles
                        && roles.contains("TEAM_LEAD");

        boolean rolesMatch = switch (account.getRole()) {
            case ADMIN -> tokenAdmin && !tokenTeamLead;
            case TEAM_LEAD -> tokenTeamLead && !tokenAdmin;
            case DEVELOPER -> !tokenAdmin && !tokenTeamLead;
        };

        if (!rolesMatch) {
            writeError(
                    response,
                    HttpServletResponse.SC_FORBIDDEN,
                    "ROLE_CHANGED",
                    "User role changed. Sign in again to refresh permissions."
            );
            return;
        }

        SessionEnforcementService.Decision decision;

        try {
            decision = sessionService.checkAndTouch(
                    sessionId,
                    userSubject
            );
        } catch (CannotAcquireLockException exception) {

            log.error(
                    "Session validation failed because of a database locking problem. "
                            + "Session ID: {}, User subject: {}",
                    sessionId,
                    userSubject,
                    exception
            );

            writeError(
                    response,
                    HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                    "SESSION_CHECK_UNAVAILABLE",
                    "Session validation is temporarily unavailable. Please retry."
            );
            return;
        }

        if (decision != SessionEnforcementService.Decision.ALLOWED) {

            String code =
                    decision == SessionEnforcementService.Decision.INACTIVITY_TIMEOUT
                            ? "SESSION_INACTIVE"
                            : "SESSION_MAX_DURATION";

            String message =
                    decision == SessionEnforcementService.Decision.INACTIVITY_TIMEOUT
                            ? "Session expired due to inactivity."
                            : "Maximum session duration exceeded.";

            writeError(
                    response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    code,
                    message
            );
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void writeError(
            HttpServletResponse response,
            int status,
            String code,
            String message
    ) throws IOException {

        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Cache-Control", "no-store");

        objectMapper.writeValue(
                response.getOutputStream(),
                Map.of(
                        "code", code,
                        "message", message
                )
        );
    }
}
