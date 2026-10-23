package unibl.sni.securevault.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import unibl.sni.securevault.service.MfaService;
import unibl.sni.securevault.service.UserService;

import java.io.IOException;
import java.util.UUID;

/**
 * Enforces MFA completion for protected endpoints.
 * <p>When the authenticated user has MFA enabled, the request's JWT must carry
 * proof that MFA was completed in this session: either a backend-issued session
 * token with an {@code mfa=true} claim, or a Keycloak JWT whose {@code amr}
 * claim includes {@code otp}. Without such proof, the request is rejected with
 * 403 Forbidden.
 * <p>Endpoints under {@code /api/auth/**} are excluded (they handle their own
 * authentication and MFA flows).
 */
@Component
public class MfaAuthenticationFilter extends OncePerRequestFilter {

    private final MfaService mfaService;
    private final UserService userService;

    public MfaAuthenticationFilter(MfaService mfaService, UserService userService) {
        this.mfaService = mfaService;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        if (path.startsWith("/api/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof Jwt jwt)) {
            filterChain.doFilter(request, response);
            return;
        }

        String keycloakId = jwt.getSubject();
        if (keycloakId == null || keycloakId.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        UUID userId = userService.findByKeycloakId(keycloakId)
                .map(unibl.sni.securevault.entity.User::getId)
                .orElse(null);
        if (userId == null) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!mfaService.isMfaEnabled(userId)) {
            filterChain.doFilter(request, response);
            return;
        }

        // MFA is enabled for this user: require proof of MFA completion.
        boolean mfaCompleted = Boolean.TRUE.equals(jwt.getClaim("mfa"))
                || "otp".equals(jwt.getClaimAsString("amr"))
                || (jwt.getClaim("amr") instanceof java.util.List<?> amrList
                && amrList.contains("otp"));

        if (!mfaCompleted) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"error\":\"forbidden\",\"message\":\"Multi-factor authentication is required\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
