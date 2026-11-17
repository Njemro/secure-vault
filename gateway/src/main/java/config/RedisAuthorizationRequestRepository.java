package config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Stores OIDC authorization requests server-side in Redis, keyed by the
 * unpredictable OAuth state value. This avoids relying on a browser session
 * cookie during the cross-site OIDC callback, so the application session cookie
 * can safely use SameSite=Strict.
 */
public final class RedisAuthorizationRequestRepository
        implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final String KEY_PREFIX = "secure-vault:oidc:request:";
    private static final Duration TTL = Duration.ofMinutes(10);

    private final ReactiveStringRedisTemplate redis;
    private final ObjectMapper mapper = new ObjectMapper();

    public RedisAuthorizationRequestRepository(ReactiveStringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {
        String state = exchange.getRequest().getQueryParams().getFirst("state");
        if (state == null || state.isBlank()) {
            return Mono.empty();
        }
        return redis.opsForValue().get(key(state))
                .flatMap(this::deserialize)
                .onErrorResume(error -> Mono.empty());
    }

    @Override
    public Mono<Void> saveAuthorizationRequest(
            OAuth2AuthorizationRequest authorizationRequest,
            ServerWebExchange exchange) {
        if (authorizationRequest == null) {
            return removeAuthorizationRequest(exchange).then();
        }
        if (authorizationRequest.getState() == null || authorizationRequest.getState().isBlank()) {
            return Mono.error(new IllegalArgumentException("OIDC authorization request has no state."));
        }
        return serialize(authorizationRequest)
                .flatMap(json -> redis.opsForValue().set(
                        key(authorizationRequest.getState()), json, TTL))
                .then();
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange exchange) {
        String state = exchange.getRequest().getQueryParams().getFirst("state");
        if (state == null || state.isBlank()) {
            return Mono.empty();
        }
        String redisKey = key(state);
        return redis.opsForValue().get(redisKey)
                .flatMap(json -> deserialize(json)
                        .flatMap(request -> redis.delete(redisKey).thenReturn(request)))
                .switchIfEmpty(redis.delete(redisKey).then(Mono.<OAuth2AuthorizationRequest>empty()));
    }

    private Mono<String> serialize(OAuth2AuthorizationRequest request) {
        try {
            StoredRequest stored = new StoredRequest(
                    request.getAuthorizationUri(),
                    request.getAuthorizationRequestUri(),
                    request.getClientId(),
                    request.getRedirectUri(),
                    request.getScopes(),
                    request.getState(),
                    request.getAdditionalParameters(),
                    request.getAttributes());
            return Mono.just(mapper.writeValueAsString(stored));
        } catch (JsonProcessingException exception) {
            return Mono.error(new IllegalStateException("Could not store OIDC authorization request.", exception));
        }
    }

    private Mono<OAuth2AuthorizationRequest> deserialize(String json) {
        try {
            StoredRequest stored = mapper.readValue(json, StoredRequest.class);
            OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri(stored.authorizationUri())
                    .authorizationRequestUri(stored.authorizationRequestUri())
                    .clientId(stored.clientId())
                    .redirectUri(stored.redirectUri())
                    .scopes(stored.scopes())
                    .state(stored.state())
                    .additionalParameters(parameters -> parameters.putAll(stored.additionalParameters()))
                    .attributes(attributes -> attributes.putAll(stored.attributes()));
            return Mono.just(builder.build());
        } catch (Exception exception) {
            return Mono.error(new IllegalStateException("Could not restore OIDC authorization request.", exception));
        }
    }

    private static String key(String state) {
        return KEY_PREFIX + state;
    }

    private record StoredRequest(
            String authorizationUri,
            String authorizationRequestUri,
            String clientId,
            String redirectUri,
            Set<String> scopes,
            String state,
            Map<String, Object> additionalParameters,
            Map<String, Object> attributes) {
        private StoredRequest {
            additionalParameters = additionalParameters == null
                    ? Map.of() : new HashMap<>(additionalParameters);
            attributes = attributes == null ? Map.of() : new HashMap<>(attributes);
            scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        }
    }
}
