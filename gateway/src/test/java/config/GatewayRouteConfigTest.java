package config;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.OrderedGatewayFilter;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import gateway.SecureVaultGatewayApplication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Focused tests for the gateway route configuration.
 *
 * <p>These tests inspect the configured {@link Route} objects directly,
 * evaluate their predicates with a mocked {@link ServerWebExchange}, and check
 * that the rate limiter filter and its per-route limits are wired. They do not
 * start the backend, Keycloak or Redis and require no network access.
 */
@SpringBootTest(classes = SecureVaultGatewayApplication.class)
class GatewayRouteConfigTest {

    @Autowired
    private RouteLocator routeLocator;

    @Value("${gateway.routes.api.uri:http://localhost:8081}")
    private String backendUri;

    @Autowired
    private RedisRateLimiter redisRateLimiter;

    @Value("${spring.cloud.gateway.server.webflux.redis-rate-limiter.config.api-backend.replenish-rate}")
    private int expectedReplenishRate;

    @Value("${spring.cloud.gateway.server.webflux.redis-rate-limiter.config.api-backend.burst-capacity}")
    private int expectedBurstCapacity;

    @Value("${spring.cloud.gateway.server.webflux.redis-rate-limiter.config.api-backend.requested-tokens}")
    private int expectedRequestedTokens;

    private Route apiRoute() {
        List<Route> routes = routeLocator.getRoutes().collectList().block();
        assertThat(routes).isNotNull();
        assertThat(routes).hasSize(2);
        return routes.stream()
                .filter(candidate -> candidate.getId().equals("api-backend"))
                .findFirst()
                .orElseThrow();
    }

    @Test
    void apiRouteForwardsToConfiguredBackend() {
        Route route = apiRoute();
        assertThat(route.getUri().toString()).isEqualTo(backendUri);
    }

    @Test
    void apiRouteMatchesApiPaths() {
        Route route = apiRoute();
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/secrets").build());
        assertThat(Mono.from(route.getPredicate().apply(exchange)).block()).isTrue();
    }

    @Test
    void apiRouteDoesNotMatchNonApiPaths() {
        Route route = apiRoute();
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/health").build());
        assertThat(Mono.from(route.getPredicate().apply(exchange)).block()).isFalse();
    }

    @Test
    void apiRouteAppliesRateLimiterAndTokenRelay() {
        Route route = apiRoute();
        assertThat(route.getFilters()).hasSize(2);
        assertThat(route.getFilters().stream().map(GatewayRouteConfigTest::delegateOf)
                .map(filter -> filter.getClass().getName()).toList())
                .anyMatch(name -> name.contains("RequestRateLimiterGatewayFilterFactory"))
                .anyMatch(name -> name.contains("TokenRelayGatewayFilterFactory"));
    }

    @Test
    void apiPrefixIsPreservedWhenForwarding() {
        Route route = apiRoute();
        // The route applies rate limiting and TokenRelay only; no StripPrefix / RewritePath
        // filter rewrites the path, so the /api prefix is forwarded unchanged.
        assertThat(route.getFilters()).hasSize(2);
        assertThat(route.getFilters().stream().map(GatewayRouteConfigTest::delegateOf)
                .map(filter -> filter.getClass().getName()).toList())
                .noneMatch(name -> name.contains("StripPrefix") || name.contains("RewritePath"));
    }


    @Test
    void publicRegistrationHasItsOwnRouteWithoutTokenRelay() {
        List<Route> routes = routeLocator.getRoutes().collectList().block();
        assertThat(routes).isNotNull();
        Route registration = routes.stream()
                .filter(candidate -> candidate.getId().equals("api-registration"))
                .findFirst()
                .orElseThrow();
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/auth/register").build());
        assertThat(Mono.from(registration.getPredicate().apply(exchange)).block()).isTrue();
        assertThat(registration.getFilters()).hasSize(1);
        assertThat(delegateOf(registration.getFilters().get(0)).getClass().getName())
                .contains("RequestRateLimiterGatewayFilterFactory");
    }

    @Test
    void apiBackendRateLimitsAreBoundFromConfiguration() {
        RedisRateLimiter.Config config = redisRateLimiter.getConfig().get("api-backend");
        assertThat(config)
                .as("rate limits for route id 'api-backend' must be bound from application.yml")
                .isNotNull();
        assertThat(config.getReplenishRate()).isEqualTo(expectedReplenishRate);
        assertThat(config.getBurstCapacity()).isEqualTo(expectedBurstCapacity);
        assertThat(config.getRequestedTokens()).isEqualTo(expectedRequestedTokens);
    }

    /** Unwraps an {@link OrderedGatewayFilter} to the factory-produced delegate. */
    private static Object delegateOf(GatewayFilter filter) {
        return filter instanceof OrderedGatewayFilter ordered ? ordered.getDelegate() : filter;
    }
}
