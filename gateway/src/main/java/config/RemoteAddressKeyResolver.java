package config;

import java.net.InetSocketAddress;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Rate-limit key resolver that keys on the client's remote socket address.
 *
 * <p>{@code X-Forwarded-For} and other forwarding headers are deliberately
 * ignored: they are attacker-controlled, so trusting them would let a client
 * pick an arbitrary rate-limit bucket. The TCP peer address cannot be forged
 * from request headers.
 *
 * <p>Only the IP part of the socket address is used. The remote port is an
 * ephemeral per-connection port; including it would give every new TCP
 * connection its own bucket and effectively disable rate limiting.
 *
 * <p>This resolver is {@link Primary} so that it also backs the gateway's
 * default {@code RequestRateLimiter} behaviour, overriding the auto-configured
 * {@code PrincipalNameKeyResolver} (which relies on an authenticated principal
 * that is not present on every proxied request). Without {@code @Primary} the
 * gateway would fail to start with an ambiguous {@link KeyResolver} injection.
 *
 * <p>When no remote address is available the returned {@code Mono} is empty.
 * The {@code RequestRateLimiter} filter treats an empty key as a violation when
 * {@code denyEmptyKey} is {@code true} (the default) and answers 403.
 */
@Component
@Primary
public class RemoteAddressKeyResolver implements KeyResolver {

    @Override
    public Mono<String> resolve(ServerWebExchange exchange) {
        InetSocketAddress remoteAddress = exchange.getRequest().getRemoteAddress();
        if (remoteAddress == null) {
            return Mono.empty();
        }
        // Prefer the resolved IP; fall back to the literal host when unresolved.
        String host = remoteAddress.getAddress() != null
                ? remoteAddress.getAddress().getHostAddress()
                : remoteAddress.getHostString();
        return Mono.just(host);
    }
}
