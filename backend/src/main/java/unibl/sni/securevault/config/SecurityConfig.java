package unibl.sni.securevault.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Explicit Spring Security foundation for the Secure Vault backend.
 *
 * <p>The backend is a stateless OAuth2 <em>resource server</em>: every
 * application request must carry a valid Keycloak-issued JWT. This replaces
 * Spring Boot's generated default HTTP Basic authentication. It does not
 * implement login, cookies, refresh-token rotation, rate limiting, or role
 * loading - those belong to later tasks.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // Default-deny: only authenticated requests reach the app.
                // No health endpoint exists yet, so nothing is permitted here.
                .anyRequest().authenticated())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Stateless bearer-token resource server. HTTP Basic and form login
            // are intentionally NOT configured; there is no session or cookie.
            // CSRF is explicitly disabled because CSRF only protects ambient
            // cookie/session credentials, which this API never uses
            // (Authorization: Bearer header only). Leaving it enabled would
            // rely on fragile incidental pass-through for unsafe methods.
            // The future API Gateway - a SEPARATE application with its own
            // SecurityFilterChain - owns CSRF protection for the browser
            // cookie-based BFF flow; disabling it here does not weaken that.
            .csrf(csrf -> csrf.disable())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            // Predictable 401 for unauthenticated requests (Bearer challenge),
            // without exposing tokens, claims, or internal configuration.
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(bearerTokenAuthenticationEntryPoint()));
        return http.build();
    }

    @Bean
    AuthenticationEntryPoint bearerTokenAuthenticationEntryPoint() {
        return new BearerTokenAuthenticationEntryPoint();
    }

    /**
     * The single {@link JwtDecoder} for the resource server. Spring Boot's
     * auto-configuration for this bean is {@code @ConditionalOnMissingBean}, so
     * defining it here takes over decoder creation entirely.
     *
     * <ul>
     *   <li>Issuer configured (env var): validate signature, expiry and issuer
     *       against Keycloak's published JWKS. Keycloak must be reachable at
     *       startup in this scenario.</li>
     *   <li>Issuer blank (tests / un-provisioned dev): fail closed - every
     *       presented token is rejected. This never permits all requests; it
     *       only avoids requiring a live Keycloak when none is configured.</li>
     * </ul>
     */
    @Bean
    JwtDecoder jwtDecoder(
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") String issuerUri) {
        if (issuerUri == null || issuerUri.isBlank()) {
            // Throw BadJwtException (a JwtException subclass): the resource
            // server maps it to InvalidBearerTokenException and a 401 - exactly
            // like a malformed token in production. A plain JwtException would
            // instead surface as a 500 AuthenticationServiceException.
            return token -> {
                throw new BadJwtException("Token validation is unavailable");
            };
        }
        return JwtDecoders.fromIssuerLocation(issuerUri);
    }
}
