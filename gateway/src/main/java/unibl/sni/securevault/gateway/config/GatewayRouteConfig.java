package unibl.sni.securevault.gateway.config;

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
 * <p>Security controls (JWT validation, cookies/BFF sessions, Redis rate
 * limiting, CORS policy, Keycloak login) are intentionally not configured
 * here yet; they are added in later tasks.
 */
@Configuration
public class GatewayRouteConfig {

    @Bean
    public RouteLocator secureVaultRouteLocator(
            RouteLocatorBuilder builder,
            @Value("${gateway.routes.api.uri:http://localhost:8081}") String backendUri) {
        return builder.routes()
                .route("api-backend", r -> r
                        .path("/api/**")
                        .uri(backendUri))
                .build();
    }
}
