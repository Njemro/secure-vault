package unibl.sni.securevault.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import unibl.sni.securevault.filter.MfaAuthenticationFilter;

/**
 * Spring Security configuration for the Secure Vault backend.
 *
 * <p>The backend is a stateless OAuth2 resource server: every application
 * request must carry a valid Keycloak-issued JWT (or a backend-issued session
 * token after MFA verification). Authentication endpoints under
 * {@code /api/auth/**} are permit-all so unauthenticated clients can register,
 * log in, and complete MFA.
 *
 * <p>MFA enforcement is handled by {@link MfaAuthenticationFilter}: when a
 * user has MFA enabled, every protected request must present a token that
 * proves MFA was completed (a backend-issued session token with {@code mfa}
 * claim, or a Keycloak JWT with an {@code amr} claim containing {@code otp}).
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            MfaAuthenticationFilter mfaAuthenticationFilter) throws Exception {
        http
            // Authentication endpoints are open; everything else requires auth.
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/register", "/api/auth/login",
                        "/api/auth/mfa/verify", "/api/auth/mfa/enroll",
                        "/api/auth/mfa/confirm", "/api/auth/mfa/disable",
                        "/api/auth/mfa/status").permitAll()
                .anyRequest().authenticated())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            // MFA enforcement filter: runs after JWT authentication, before
            // the request reaches the application controller.
            .addFilterBefore(mfaAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(bearerTokenAuthenticationEntryPoint()));
        return http.build();
    }

    @Bean
    AuthenticationEntryPoint bearerTokenAuthenticationEntryPoint() {
        return new BearerTokenAuthenticationEntryPoint();
    }

    @Bean
    JwtDecoder jwtDecoder(
            @Value("${KEYCLOAK_ISSUER_URI:}") String issuerUri) {
        if (issuerUri == null || issuerUri.isBlank()) {
            return token -> {
                throw new BadJwtException("Token validation is unavailable");
            };
        }
        return JwtDecoders.fromIssuerLocation(issuerUri);
    }
}


