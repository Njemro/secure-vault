package config;

import java.net.InetSocketAddress;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RemoteAddressKeyResolver}.
 *
 * <p>These are plain unit tests: no Spring context, no gateway, no Redis and no
 * network access.
 */
class RemoteAddressKeyResolverTest {

    private final RemoteAddressKeyResolver resolver = new RemoteAddressKeyResolver();

    @Test
    void resolvesToRemoteSocketAddressIp() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/secrets")
                        .remoteAddress(new InetSocketAddress("127.0.0.1", 49152))
                        .build());

        assertThat(Mono.from(resolver.resolve(exchange)).block())
                .isEqualTo("127.0.0.1");
    }

    @Test
    void ignoresXForwardedForHeader() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/secrets")
                        .remoteAddress(new InetSocketAddress("127.0.0.1", 49152))
                        .header("X-Forwarded-For", "198.51.100.9")
                        .header("X-Real-IP", "198.51.100.10")
                        .build());

        // The socket address wins; forged forwarding headers are never used.
        assertThat(Mono.from(resolver.resolve(exchange)).block())
                .isEqualTo("127.0.0.1");
    }

    @Test
    void usesHostStringWhenAddressIsUnresolved() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/secrets")
                        .remoteAddress(InetSocketAddress.createUnresolved("203.0.113.7", 49152))
                        .build());

        assertThat(Mono.from(resolver.resolve(exchange)).block())
                .isEqualTo("203.0.113.7");
    }

    @Test
    void returnsEmptyWhenNoRemoteAddress() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/secrets").build());

        // Empty key -> RequestRateLimiter denyEmptyKey (default true) -> 403.
        assertThat(Mono.from(resolver.resolve(exchange)).blockOptional()).isEmpty();
    }
}
