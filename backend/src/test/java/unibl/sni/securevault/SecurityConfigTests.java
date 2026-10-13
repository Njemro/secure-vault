package unibl.sni.securevault;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Focused tests for the Task 9A security foundation. They verify the explicit
 * security beans exist, that unauthenticated access is rejected with 401, and
 * that an invalid bearer token is rejected with 401. No running Keycloak or
 * real credentials are required: the test profile uses the fail-closed decoder.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityConfigTests {

    @Autowired
    private SecurityFilterChain securityFilterChain;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void securityBeansAreConfigured() {
        assertNotNull(securityFilterChain, "SecurityFilterChain must replace the default");
        assertNotNull(jwtDecoder, "JwtDecoder must be present for the resource server");
    }

    @Test
    void unauthenticatedRequestIsRejectedWith401AndBearerChallenge() throws Exception {
        mockMvc.perform(get("/api/secrets"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("Bearer")));
    }

    @Test
    void invalidBearerTokenIsRejectedWith401() throws Exception {
        mockMvc.perform(get("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-valid-jwt"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void authenticatedWriteWithBearerTokenIsNotBlockedByCsrf() throws Exception {
        // A bearer-token-only API must not be blocked by CSRF for unsafe methods.
        // With CSRF active this POST is rejected with 403 before authentication.
        // The correct behavior is 401: the request reaches the resource server and
        // the fail-closed test decoder rejects the (invalid) token. (Unauthorized,
        // not Forbidden, proves CSRF did not intercept it.)
        mockMvc.perform(post("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-valid-jwt"))
                .andExpect(status().isUnauthorized());
    }
}
