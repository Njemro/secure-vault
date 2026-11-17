package gateway.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class BffAuthController {

    /** Returns identity claims, never the access or refresh token. */
    @GetMapping("/auth/me")
    public Mono<ResponseEntity<Map<String, Object>>> currentUser(Mono<Authentication> authentication) {
        return authentication
                .filter(auth -> auth.isAuthenticated() && auth.getAuthorities().stream()
                        .noneMatch(authority -> "ROLE_ANONYMOUS".equals(authority.getAuthority())))
                .map(auth -> {
                    Map<String, Object> result = new HashMap<>();
                    Object principal = auth.getPrincipal();
                    if (principal instanceof OidcUser oidcUser) {
                        result.putAll(oidcUser.getClaims());
                    } else if (principal instanceof OAuth2User oauth2User) {
                        result.putAll(oauth2User.getAttributes());
                    }

                    List<String> roles = new ArrayList<>();
                    for (GrantedAuthority authority : auth.getAuthorities()) {
                        String name = authority.getAuthority();
                        if (name.startsWith("ROLE_")) {
                            roles.add(name.substring("ROLE_".length()));
                        }
                    }
                    if (!roles.isEmpty()) {
                        result.put("realm_access", Map.of("roles", roles));
                    }
                    result.put("authenticated", true);
                    return ResponseEntity.ok(result);
                })
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.<String, Object>of("authenticated", false)));
    }

    /** CSRF token is returned in JSON; no JavaScript-readable session cookie is needed. */
    @GetMapping("/auth/csrf")
    public Mono<Map<String, String>> csrfToken(ServerWebExchange exchange) {
        Mono<CsrfToken> token = exchange.getAttribute(CsrfToken.class.getName());
        if (token == null) {
            return Mono.error(new IllegalStateException("CSRF token is not available."));
        }
        return token.map(value -> Map.of(
                "token", value.getToken(),
                "headerName", value.getHeaderName()));
    }
}
