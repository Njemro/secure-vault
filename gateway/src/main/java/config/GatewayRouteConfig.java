package config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Route configuration for the Secure Vault API Gateway.
 *
 * <p>The gateway is the SPA edge/BFF: it forwards {@code /api/**} to the
 * backend and keeps OAuth tokens server-side. The {@code /api} prefix is
 * preserved because the backend serves its API under {@code /api}.
 *
 * <p>The protected API route applies Redis-backed request limiting keyed by
 * {@link RemoteAddressKeyResolver} (remote socket address, never
 * {@code X-Forwarded-For}) and TokenRelay. Public registration has a separate,
 * stricter rate-limit route and does not use TokenRelay.
 *
 * <p>The gateway is also the OIDC BFF: TokenRelay obtains the access token
 * from the server-side WebSession and forwards it to the resource server.
 * The browser never receives OAuth access/refresh tokens.
 */
@Configuration
public class GatewayRouteConfig {

    @Bean
    public RouteLocator secureVaultRouteLocator(
            RouteLocatorBuilder builder,
            @Value("${gateway.routes.api.uri:http://localhost:8081}") String backendUri,
            RemoteAddressKeyResolver remoteAddressKeyResolver) {
        return builder.routes()
                // Public registration is routed without TokenRelay.
                .route("api-registration", r -> r
                        .path("/api/auth/register")
                        .filters(f -> f.requestRateLimiter(
                                cfg -> cfg.setKeyResolver(remoteAddressKeyResolver)))
                        .uri(backendUri))
                .route("api-backend", r -> r
                        .path("/api/**")
                        .filters(f -> f
                                .requestRateLimiter(cfg -> cfg.setKeyResolver(remoteAddressKeyResolver))
                                .tokenRelay())
                        .uri(backendUri))
                .build();
    }
}
