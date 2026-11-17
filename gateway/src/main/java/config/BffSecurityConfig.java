package config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import java.net.URI;
import java.util.Map;
import org.springframework.security.web.server.csrf.WebSessionServerCsrfTokenRepository;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;

@Configuration
@EnableWebFluxSecurity
@EnableRedisWebSession(maxInactiveIntervalInSeconds = 1800, redisNamespace = "secure-vault:bff:sessions")
public class BffSecurityConfig {

    @Bean
    SecurityWebFilterChain gatewaySecurityWebFilterChain(
            ServerHttpSecurity http,
            ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository,
            ServerLogoutSuccessHandler oidcLogoutSuccessHandler,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {

        return http
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(
                                "/oauth2/**",
                                "/login/**",
                                "/auth/me",
                                "/auth/csrf",
                                "/api/auth/register",
                                "/actuator/health"
                        ).permitAll()
                        .anyExchange().authenticated())
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((exchange, authException) -> {
                            if (exchange.getRequest().getURI().getPath().startsWith("/api/")) {
                                exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
                                exchange.getResponse().getHeaders().add("Cache-Control", "no-store");
                                return exchange.getResponse().setComplete();
                            }
                            return new RedirectServerAuthenticationEntryPoint(
                                    "/oauth2/authorization/keycloak").commence(exchange, authException);
                        }))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(new WebSessionServerCsrfTokenRepository()))
                .oauth2Login(oauth2 -> oauth2
                        .authorizationRequestRepository(authorizationRequestRepository)
                        .authenticationSuccessHandler(loginSuccessHandler())
                        .authorizedClientRepository(authorizedClientRepository))
                .oauth2Client(Customizer.withDefaults())
                .logout(logout -> logout
                        .logoutUrl("/auth/logout")
                        .logoutSuccessHandler(oidcLogoutSuccessHandler))
                .build();
    }


    private static ServerAuthenticationSuccessHandler loginSuccessHandler() {
        RedirectServerAuthenticationSuccessHandler redirect = new RedirectServerAuthenticationSuccessHandler();
        redirect.setLocation(URI.create("/dashboard"));

        // Rotate the opaque server-side session identifier after successful
        // authentication to prevent session fixation.
        return (webFilterExchange, authentication) ->
                webFilterExchange.getExchange().getSession()
                        .flatMap(session -> session.changeSessionId())
                        .then(redirect.onAuthenticationSuccess(webFilterExchange, authentication));
    }

    /** The browser receives only an opaque server-side session identifier. */
    @Bean
    WebSessionIdResolver webSessionIdResolver() {
        CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();
        resolver.setCookieName("__Host-SVSESSION");
        resolver.addCookieInitializer((ResponseCookie.ResponseCookieBuilder cookie) -> cookie
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Strict"));
        return resolver;
    }

    /** Explicit endpoint registration avoids discovery network calls during Gateway startup. */
    @Bean
    ReactiveClientRegistrationRepository clientRegistrationRepository(
            @Value("${gateway.oidc.issuer-uri:http://localhost:8080/realms/secure-vault}") String issuerUri,
            @Value("${gateway.oidc.authorization-uri:http://localhost:8080/realms/secure-vault/protocol/openid-connect/auth}") String authorizationUri,
            @Value("${gateway.oidc.token-uri:http://localhost:8080/realms/secure-vault/protocol/openid-connect/token}") String tokenUri,
            @Value("${gateway.oidc.jwk-set-uri:http://localhost:8080/realms/secure-vault/protocol/openid-connect/certs}") String jwkSetUri,
            @Value("${gateway.oidc.user-info-uri:http://localhost:8080/realms/secure-vault/protocol/openid-connect/userinfo}") String userInfoUri,
            @Value("${KEYCLOAK_BFF_CLIENT_ID:secure-vault-bff}") String clientId,
            @Value("${KEYCLOAK_BFF_CLIENT_SECRET}") String clientSecret,
            @Value("${OIDC_REDIRECT_URI:http://localhost:5173/login/oauth2/code/keycloak}") String redirectUri) {
        ClientRegistration registration = ClientRegistration.withRegistrationId("keycloak")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .scope("openid", "profile", "email")
                .authorizationUri(authorizationUri)
                .tokenUri(tokenUri)
                .jwkSetUri(jwkSetUri)
                .userInfoUri(userInfoUri)
                .userNameAttributeName("preferred_username")
                .issuerUri(issuerUri)
                .providerConfigurationMetadata(Map.of(
                        "end_session_endpoint", issuerUri + "/protocol/openid-connect/logout"))
                .clientName("Secure Vault Keycloak")
                .build();
        return new InMemoryReactiveClientRegistrationRepository(registration);
    }

    @Bean
    ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new WebSessionServerOAuth2AuthorizedClientRepository();
    }

    /** Refreshes the access token with the OIDC refresh token when it expires. */
    @Bean
    ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
            ReactiveClientRegistrationRepository registrations,
            ServerOAuth2AuthorizedClientRepository authorizedClients,
            @Value("${OIDC_TOKEN_REFRESH_CLOCK_SKEW_SECONDS:5}") long refreshClockSkewSeconds) {
        DefaultReactiveOAuth2AuthorizedClientManager manager =
                new DefaultReactiveOAuth2AuthorizedClientManager(registrations, authorizedClients);
        ReactiveOAuth2AuthorizedClientProvider provider = ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken(refresh -> refresh.clockSkew(java.time.Duration.ofSeconds(refreshClockSkewSeconds)))
                .build();
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    @Bean
    ServerLogoutSuccessHandler oidcLogoutSuccessHandler(
            ReactiveClientRegistrationRepository registrations,
            @Value("${OIDC_POST_LOGOUT_REDIRECT_URI:http://localhost:5173/login?logged_out}") String postLogoutRedirectUri) {
        OidcClientInitiatedServerLogoutSuccessHandler handler =
                new OidcClientInitiatedServerLogoutSuccessHandler(registrations);
        handler.setPostLogoutRedirectUri(postLogoutRedirectUri);
        return handler;
    }

    @Bean
    ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> redisAuthorizationRequestRepository(
            ReactiveStringRedisTemplate redis) {
        return new RedisAuthorizationRequestRepository(redis);
    }
}
