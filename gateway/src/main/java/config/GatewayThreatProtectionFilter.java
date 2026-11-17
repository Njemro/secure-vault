
package config;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Redis-backed edge protection.
 * Rate-limits OIDC login initiation, detects suspicious SQL patterns,
 * temporarily blocks noisy IPs and counts unauthorized API responses
 * and failed decryption attempts.
 *
 * X-Forwarded-For is intentionally ignored because clients can forge it.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class GatewayThreatProtectionFilter implements WebFilter {

    private static final RedisScript<Long> INCREMENT_WITH_TTL = RedisScript.of("""
            local count = redis.call('INCR', KEYS[1])
            local ttl = redis.call('PTTL', KEYS[1])
            if ttl < 0 then
                redis.call('PEXPIRE', KEYS[1], ARGV[1])
            end
            return count
            """, Long.class);

    private static final Duration LOGIN_WINDOW = Duration.ofMinutes(5);
    private static final Duration SIGNAL_WINDOW = Duration.ofMinutes(5);
    private static final Duration BLOCK_DURATION = Duration.ofMinutes(15);
    private static final long MAX_LOGIN_STARTS = 8;
    private static final long MAX_SUSPICIOUS_SIGNALS = 3;
    private static final long MAX_UNAUTHORIZED_RESPONSES = 10;

    private static final Pattern SQL_INJECTION = Pattern.compile(
            "(?is)(?:%27|')\\s*(?:or|and)\\s*(?:%27|'|[0-9]).{0,40}(?:=|%3d)"
                    + "|\\bunion\\s+(?:all\\s+)?select\\b"
                    + "|;\\s*(?:drop|alter|truncate)\\s+"
                    + "|/\\*.*?\\*/"
                    + "|\\bsleep\\s*\\("
                    + "|\\bbenchmark\\s*\\("
                    + "|\\binformation_schema\\b"
                    + "|(?:--|%2d%2d)\\s*$");

    private final ReactiveStringRedisTemplate redis;

    public GatewayThreatProtectionFilter(ReactiveStringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String ip = clientIp(exchange);
        String blockKey = "secure-vault:threat:block:" + ip;

        return redis.hasKey(blockKey).flatMap(blocked -> {
            if (Boolean.TRUE.equals(blocked)) {
                return reject(
                        exchange,
                        HttpStatus.TOO_MANY_REQUESTS,
                        "IP_TEMPORARILY_BLOCKED",
                        "Too many suspicious requests. Try again later."
                );
            }

            String path = exchange.getRequest().getURI().getRawPath();
            String query = exchange.getRequest().getURI().getRawQuery();
            String rawTarget = path + "?" + (query == null ? "" : query);

            String target;
            try {
                target = URLDecoder.decode(
                        rawTarget,
                        StandardCharsets.UTF_8
                ).toLowerCase(Locale.ROOT);
            } catch (IllegalArgumentException malformedEncoding) {
                target = rawTarget.toLowerCase(Locale.ROOT);
            }

            // OIDC login rate limiting
            if (path.startsWith("/oauth2/authorization/")) {
                return increment(
                        "secure-vault:threat:oidc-login:" + ip,
                        LOGIN_WINDOW
                ).flatMap(count -> {
                    if (count > MAX_LOGIN_STARTS) {
                        return block(ip).then(
                                reject(
                                        exchange,
                                        HttpStatus.TOO_MANY_REQUESTS,
                                        "LOGIN_RATE_LIMITED",
                                        "Too many login attempts from this IP."
                                )
                        );
                    }

                    return chain.filter(exchange);
                });
            }

            // Failed decryption protection
            if (path.equals("/api/security-events/decryption-failure")) {
                String key =
                        "secure-vault:threat:decrypt-failures:" + ip;

                return redis.opsForValue()
                        .increment(key)
                        .flatMap(count -> {
                            Mono<Boolean> expiry = count == 1
                                    ? redis.expire(key, Duration.ofMinutes(10))
                                    : Mono.just(true);

                            return expiry.then(Mono.defer(() -> {
                                if (count >= 6) {
                                    return block(ip).then(
                                            reject(
                                                    exchange,
                                                    HttpStatus.TOO_MANY_REQUESTS,
                                                    "DECRYPTION_FAILURE_RATE_LIMITED",
                                                    "Too many failed decryption attempts."
                                            )
                                    );
                                }

                                return chainWithClientIp(exchange, chain, ip);
                            }));
                        })
                        .onErrorResume(error ->
                                reject(
                                        exchange,
                                        HttpStatus.SERVICE_UNAVAILABLE,
                                        "RATE_LIMITER_UNAVAILABLE",
                                        "Security service temporarily unavailable."
                                )
                        );
            }

            // SQL injection detection in URL and query
            if (path.startsWith("/api/")
                    && SQL_INJECTION.matcher(target).find()) {
                return recordSuspiciousInput(exchange, ip);
            }

            Mono<Void> downstream = path.startsWith("/api/")
                    ? scanBodyAndChain(exchange, chain, ip)
                    : chainWithClientIp(exchange, chain, ip);

            // Repeated unauthorized API responses
            return downstream.then(Mono.defer(() -> {
                if (path.startsWith("/api/")
                        && exchange.getResponse().getStatusCode()
                        == HttpStatus.UNAUTHORIZED) {

                    return increment(
                            "secure-vault:threat:unauthorized:" + ip,
                            SIGNAL_WINDOW
                    ).flatMap(count ->
                            count >= MAX_UNAUTHORIZED_RESPONSES
                                    ? block(ip).then()
                                    : Mono.empty()
                    );
                }

                return Mono.empty();
            }));
        });
    }

    private Mono<Void> scanBodyAndChain(
            ServerWebExchange exchange,
            WebFilterChain chain,
            String ip) {

        MediaType contentType =
                exchange.getRequest().getHeaders().getContentType();

        boolean inspectable = contentType != null && (
                MediaType.APPLICATION_JSON.isCompatibleWith(contentType)
                        || MediaType.TEXT_PLAIN.isCompatibleWith(contentType)
                        || MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(contentType)
        );

        if (!inspectable) {
            return chainWithClientIp(exchange, chain, ip);
        }

        return DataBufferUtils.join(
                        exchange.getRequest().getBody(),
                        128 * 1024
                )
                .defaultIfEmpty(
                        exchange.getResponse()
                                .bufferFactory()
                                .wrap(new byte[0])
                )
                .flatMap(buffer -> {
                    byte[] body = new byte[buffer.readableByteCount()];
                    buffer.read(body);
                    DataBufferUtils.release(buffer);

                    String bodyText =
                            new String(body, StandardCharsets.UTF_8);

                    if (SQL_INJECTION.matcher(bodyText).find()) {
                        return recordSuspiciousInput(exchange, ip);
                    }

                    var decorated =
                            new ServerHttpRequestDecorator(
                                    exchange.getRequest()
                            ) {
                                @Override
                                public Flux<DataBuffer> getBody() {
                                    if (body.length == 0) {
                                        return Flux.empty();
                                    }

                                    return Flux.defer(() ->
                                            Flux.just(
                                                    exchange.getResponse()
                                                            .bufferFactory()
                                                            .wrap(body)
                                            )
                                    );
                                }

                                @Override
                                public HttpHeaders getHeaders() {
                                    HttpHeaders headers = new HttpHeaders();
                                    headers.putAll(super.getHeaders());

                                    if (headers.containsKey(
                                            HttpHeaders.CONTENT_LENGTH)) {
                                        headers.setContentLength(body.length);
                                    }

                                    return headers;
                                }
                            };

                    return chain.filter(
                            exchange.mutate()
                                    .request(decorated)
                                    .build()
                    );
                })
                .onErrorResume(
                        DataBufferLimitException.class,
                        error -> reject(
                                exchange,
                                HttpStatus.PAYLOAD_TOO_LARGE,
                                "REQUEST_TOO_LARGE",
                                "Request body exceeds the inspection limit."
                        )
                );
    }

    private Mono<Void> recordSuspiciousInput(
            ServerWebExchange exchange,
            String ip) {

        return increment(
                "secure-vault:threat:sqli:" + ip,
                SIGNAL_WINDOW
        ).flatMap(count -> {
            Mono<Boolean> ban =
                    count >= MAX_SUSPICIOUS_SIGNALS
                            ? block(ip)
                            : Mono.just(false);

            return ban.then(
                    reject(
                            exchange,
                            count >= MAX_SUSPICIOUS_SIGNALS
                                    ? HttpStatus.TOO_MANY_REQUESTS
                                    : HttpStatus.BAD_REQUEST,
                            "SUSPICIOUS_INPUT",
                            "Suspicious request pattern detected."
                    )
            );
        });
    }

    private Mono<Void> chainWithClientIp(
            ServerWebExchange exchange,
            WebFilterChain chain,
            String ip) {

        var request = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove("X-SecureVault-Client-IP");
                    headers.set("X-SecureVault-Client-IP", ip);
                })
                .build();

        return chain.filter(
                exchange.mutate()
                        .request(request)
                        .build()
        );
    }

    private Mono<Long> increment(String key, Duration window) {
        return redis.execute(
                        INCREMENT_WITH_TTL,
                        List.of(key),
                        Long.toString(window.toMillis())
                )
                .next();
    }

    private Mono<Boolean> block(String ip) {
        return redis.opsForValue().set(
                "secure-vault:threat:block:" + ip,
                "1",
                BLOCK_DURATION
        );
    }

    private static String clientIp(ServerWebExchange exchange) {
        InetSocketAddress remote =
                exchange.getRequest().getRemoteAddress();

        if (remote == null) {
            return "unknown";
        }

        return remote.getAddress() != null
                ? remote.getAddress().getHostAddress()
                : remote.getHostString();
    }

    private static Mono<Void> reject(
            ServerWebExchange exchange,
            HttpStatus status,
            String code,
            String message) {

        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders()
                .add("Cache-Control", "no-store");
        exchange.getResponse().getHeaders()
                .add("X-SecureVault-Block-Reason", code);

        return exchange.getResponse().setComplete();
    }
}
