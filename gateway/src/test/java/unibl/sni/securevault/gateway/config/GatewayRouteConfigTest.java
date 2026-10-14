package unibl.sni.securevault.gateway.config;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Focused tests for the gateway route configuration.
 *
 * <p>These tests inspect the configured {@link Route} objects directly and
 * evaluate their predicates with a mocked {@link ServerWebExchange}. They do
 * not start the backend or Keycloak and require no network access.
 */
@SpringBootTest
class GatewayRouteConfigTest {

    @Autowired
    private RouteLocator routeLocator;

    @Value("${gateway.routes.api.uri:http://localhost:8081}")
    private String backendUri;

    private Route apiRoute() {
        List<Route> routes = routeLocator.getRoutes().collectList().block();
        assertThat(routes).isNotNull();
        assertThat(routes).hasSize(1);
        Route route = routes.get(0);
        assertThat(route.getId()).isEqualTo("api-backend");
        return route;
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
    void apiPrefixIsPreservedWhenForwarding() {
        Route route = apiRoute();
        // No StripPrefix / RewritePath filter is applied, so the /api prefix is
        // forwarded to the backend unchanged.
        assertThat(route.getFilters()).isEmpty();
    }
}
