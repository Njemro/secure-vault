package config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Route configuration for the Secure Vault API Gateway.
 *
 * <p>The gateway is a thin edge proxy: it forwards {@code /api/**} to the
 * backend and adds no business logic. The {@code /api} prefix is preserved
 * when forwarding because the route intentionally applies no
 * {@code StripPrefix}/{@code RewritePath} filter - the backend serves its API
 * under {@code /api}.
 *
 * <p>The route applies one gateway filter: the Redis-backed
 * {@code RequestRateLimiter}, keyed per client by
 * {@link RemoteAddressKeyResolver} (remote socket address, never
 * {@code X-Forwarded-For}). Limits are configured under
 * {@code spring.cloud.gateway.server.webflux.redis-rate-limiter.config.api-backend}.
 *
 * <p>Note that Keycloak login traffic does <b>not</b> pass through this
 * gateway, so this rate limiter does <b>not</b> protect login attempts.
 *
 * <p>Other security controls (JWT validation, cookies/BFF sessions, CORS
 * policy) are intentionally not configured here yet; they are added in later
 * tasks.
 */
@Configuration
public class GatewayRouteConfig {

    @Bean
    public RouteLocator secureVaultRouteLocator(
            RouteLocatorBuilder builder,
            @Value("${gateway.routes.api.uri:http://localhost:8081}") String backendUri,
            RemoteAddressKeyResolver remoteAddressKeyResolver) {
        return builder.routes()
                .route("api-backend", r -> r
                        .path("/api/**")
                        .filters(f -> f.requestRateLimiter(
                                cfg -> cfg.setKeyResolver(remoteAddressKeyResolver)))
                        .uri(backendUri))
                .build();
    }
}
