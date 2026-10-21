package unibl.sni.securevault;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import unibl.sni.securevault.entity.AuditLog;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.repository.AuditLogRepository;
import unibl.sni.securevault.repository.UserRepository;
import unibl.sni.securevault.service.AuditLogService;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end tests for the owner-scoped Secret REST slice, exercising the
 * real Spring Security resource-server filter chain against the test-profile
 * database (in-memory H2). The only override is a stub {@link JwtDecoder}
 * that maps three fixed test tokens (alice, bob, an unknown subject) plus any
 * garbage string to JWTs - no Keycloak and no production configuration is
 * touched, and no test disables authentication. Binary payload fields are
 * sent as standard Base64, exactly like the browser client will.
 *
 * <p>Writes are not rolled back between tests, so each test seeds its own
 * users (unique "ctl-" suffix) and secrets.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecretControllerTests {

    private static final String ALICE_TOKEN = "test-token-alice";
    private static final String BOB_TOKEN = "test-token-bob";
    private static final String GHOST_TOKEN = "test-token-ghost";

    private static final byte[] CONTENT = {10, 20, 30, 40, 50};
    private static final byte[] WRAPPED_DEK = {1, 2, 3, 4, 5, 6, 7, 8};
    private static final byte[] CONTENT_IV = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
    private static final byte[] DEK_IV = {8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8};

    private static final byte[] NEW_CONTENT = {55, 66, 77, 88};
    private static final byte[] NEW_WRAPPED_DEK = {15, 25, 35, 45, 55, 65, 75, 85, 95};
    private static final byte[] NEW_CONTENT_IV = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
    private static final byte[] NEW_DEK_IV = {6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6};

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private AuditLogRepository auditLogRepository;
    @Autowired private AuditLogService auditLogService;

    /** Replaces only the decoder bean in this test slice; SecurityConfig is untouched. */
    @MockitoBean
    private JwtDecoder jwtDecoder;

    private String aliceKeycloakId;
    private String bobKeycloakId;

    @BeforeEach
    void seedUsersAndStubDecoder() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        aliceKeycloakId = "kc-ctl-a-" + suffix;
        bobKeycloakId = "kc-ctl-b-" + suffix;
        userRepository.save(new User(aliceKeycloakId, "ctl-alice-" + suffix,
                Role.DEVELOPER, UserStatus.ACTIVE));
        userRepository.save(new User(bobKeycloakId, "ctl-bob-" + suffix,
                Role.DEVELOPER, UserStatus.ACTIVE));

        // Lenient: the 401 tests never reach the decoder, so the stubbing is
        // intentionally unused there and must not fail strict-stub checks.
        Mockito.lenient().when(jwtDecoder.decode(anyString())).thenAnswer(invocation -> {
            String token = invocation.getArgument(0);
            return switch (token) {
                case ALICE_TOKEN -> jwtWithSubject(aliceKeycloakId);
                case BOB_TOKEN -> jwtWithSubject(bobKeycloakId);
                case GHOST_TOKEN -> jwtWithSubject("kc-ctl-ghost-" + suffix);
                // Anything else behaves exactly like an invalid token.
                default -> throw new BadJwtException("Invalid test token");
            };
        });
    }

    private static Jwt jwtWithSubject(String subject) {
        Instant now = Instant.now();
        return new Jwt("test-token", now, now.plusSeconds(300),
                Map.of("alg", "none"), Map.of("sub", subject));
    }

    private static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static String secretJson(String name, String description, byte[] value, byte[] dek,
                                     byte[] contentIv, byte[] dekIv, String algorithm) {
        String descriptionJson = description == null ? "null" : "\"" + description + "\"";
        return ("{\"name\":\"%s\",\"description\":%s,\"encryptedValue\":\"%s\",\"encryptedDek\":\"%s\","
                + "\"contentIv\":\"%s\",\"dekIv\":\"%s\",\"encryptionAlgorithm\":\"%s\"}")
                .formatted(name, descriptionJson, b64(value), b64(dek),
                        b64(contentIv), b64(dekIv), algorithm);
    }

    private static String validJson(String name) {
        return secretJson(name, null, CONTENT, WRAPPED_DEK, CONTENT_IV, DEK_IV, "AES-256-GCM");
    }

    private String createSecret(String token, String name) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validJson(name)))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("id").asText();
    }

    // ------------------------------------------------------------------
    // Authentication
    // ------------------------------------------------------------------

    @Test
    void unauthenticatedRequestsAreRejectedWith401() throws Exception {
        mockMvc.perform(get("/api/secrets")).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/secrets").contentType(MediaType.APPLICATION_JSON)
                        .content(validJson("x")))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/secrets/" + UUID.randomUUID())).andExpect(status().isUnauthorized());
        mockMvc.perform(put("/api/secrets/" + UUID.randomUUID()).contentType(MediaType.APPLICATION_JSON)
                        .content(validJson("x")))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(delete("/api/secrets/" + UUID.randomUUID())).andExpect(status().isUnauthorized());
    }

    @Test
    void invalidBearerTokenIsRejectedWith401() throws Exception {
        mockMvc.perform(get("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-valid-jwt"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validTokenForUnknownUserIsRejectedWith404() throws Exception {
        mockMvc.perform(get("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + GHOST_TOKEN))
                .andExpect(status().isNotFound());
    }

    // ------------------------------------------------------------------
    // Create and read
    // ------------------------------------------------------------------

    @Test
    void createAndRetrieveRoundTripCiphertextOnly() throws Exception {
        mockMvc.perform(post("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(secretJson("ctl-api-key", "work account", CONTENT, WRAPPED_DEK,
                                CONTENT_IV, DEK_IV, "AES-256-GCM")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.name").value("ctl-api-key"))
                .andExpect(jsonPath("$.description").value("work account"))
                .andExpect(jsonPath("$.encryptedValue").value(b64(CONTENT)))
                .andExpect(jsonPath("$.encryptedDek").value(b64(WRAPPED_DEK)))
                .andExpect(jsonPath("$.contentIv").value(b64(CONTENT_IV)))
                .andExpect(jsonPath("$.dekIv").value(b64(DEK_IV)))
                .andExpect(jsonPath("$.encryptionAlgorithm").value("AES-256-GCM"))
                .andExpect(jsonPath("$.createdAt").isNotEmpty())
                .andExpect(jsonPath("$.lastRotatedAt").doesNotExist());

        String id = createSecret(ALICE_TOKEN, "ctl-retrieve");
        mockMvc.perform(get("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.name").value("ctl-retrieve"))
                .andExpect(jsonPath("$.encryptedValue").value(b64(CONTENT)))
                .andExpect(jsonPath("$.encryptedDek").value(b64(WRAPPED_DEK)));
    }

    @Test
    void invalidCreateRequestIsRejectedWith400AndSafeDetails() throws Exception {
        mockMvc.perform(post("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(secretJson("  ", null, CONTENT, WRAPPED_DEK,
                                CONTENT_IV, DEK_IV, "AES-256-GCM")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("name")))
                .andExpect(jsonPath("$.message").value(not(containsString(b64(CONTENT)))));

        // Missing crypto fields entirely (bean validation, not service checks).
        mockMvc.perform(post("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"x\"}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(get("/api/secrets/not-a-uuid")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isBadRequest());

        // Malformed JSON: 400 with a fixed generic message, never exception internals.
        mockMvc.perform(post("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{not-valid-json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Request body is malformed or unreadable"));
    }

    @Test
    void missingSecretReturns404() throws Exception {
        mockMvc.perform(get("/api/secrets/" + UUID.randomUUID())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isNotFound());
    }

    // ------------------------------------------------------------------
    // Listing
    // ------------------------------------------------------------------

    @Test
    void listContainsOnlyCurrentUsersSecrets() throws Exception {
        createSecret(ALICE_TOKEN, "ctl-alice-only");
        createSecret(BOB_TOKEN, "ctl-bob-only");

        mockMvc.perform(get("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].name").value("ctl-alice-only"));

        mockMvc.perform(get("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].name").value("ctl-bob-only"));
    }

    // ------------------------------------------------------------------
    // Update
    // ------------------------------------------------------------------

    @Test
    void ownerCanUpdateEncryptedContent() throws Exception {
        String id = createSecret(ALICE_TOKEN, "ctl-before-update");

        mockMvc.perform(put("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(secretJson("ctl-after-update", "rotated", NEW_CONTENT, NEW_WRAPPED_DEK,
                                NEW_CONTENT_IV, NEW_DEK_IV, "AES-256-GCM")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.name").value("ctl-after-update"))
                .andExpect(jsonPath("$.description").value("rotated"))
                .andExpect(jsonPath("$.encryptedValue").value(b64(NEW_CONTENT)))
                .andExpect(jsonPath("$.encryptedDek").value(b64(NEW_WRAPPED_DEK)))
                .andExpect(jsonPath("$.contentIv").value(b64(NEW_CONTENT_IV)))
                .andExpect(jsonPath("$.dekIv").value(b64(NEW_DEK_IV)))
                .andExpect(jsonPath("$.lastRotatedAt").isNotEmpty());

        mockMvc.perform(get("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("ctl-after-update"))
                .andExpect(jsonPath("$.encryptedValue").value(b64(NEW_CONTENT)));
    }

    @Test
    void invalidUpdateRequestIsRejectedWith400() throws Exception {
        String id = createSecret(ALICE_TOKEN, "ctl-update-invalid");

        mockMvc.perform(put("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(secretJson("", null, NEW_CONTENT, NEW_WRAPPED_DEK,
                                NEW_CONTENT_IV, NEW_DEK_IV, "AES-256-GCM")))
                .andExpect(status().isBadRequest());

        mockMvc.perform(put("/api/secrets/" + UUID.randomUUID())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validJson("ctl-update-missing")))
                .andExpect(status().isNotFound());
    }

    // ------------------------------------------------------------------
    // Delete
    // ------------------------------------------------------------------

    @Test
    void ownerCanDeleteSecretAndItDisappears() throws Exception {
        String id = createSecret(ALICE_TOKEN, "ctl-to-delete");

        mockMvc.perform(delete("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isNotFound());

        mockMvc.perform(delete("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isNotFound());
    }

    // ------------------------------------------------------------------
    // Cross-user access
    // ------------------------------------------------------------------

    @Test
    void otherUsersSecretCannotBeReadUpdatedOrDeleted() throws Exception {
        String id = createSecret(ALICE_TOKEN, "ctl-owners-eyes-only");

        mockMvc.perform(get("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN))
                .andExpect(status().isBadRequest());

        mockMvc.perform(put("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validJson("ctl-hijacked")))
                .andExpect(status().isBadRequest());

        mockMvc.perform(delete("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN))
                .andExpect(status().isBadRequest());

        // The secret is untouched and still owned by alice.
        MvcResult result = mockMvc.perform(get("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk())
                .andReturn();
        String body = result.getResponse().getContentAsString();
        assertFalse(body.contains("ctl-hijacked"), "another user must not be able to rename the secret");

        String bobList = mockMvc.perform(get("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertFalse(bobList.contains(id), "the list endpoint must never expose another user's secret id");
    }

    // ------------------------------------------------------------------
    // Audit hash chain
    // ------------------------------------------------------------------

    @Test
    void successfulCrudActionsAreRecordedInTheAuditChain() throws Exception {
        String id = createSecret(ALICE_TOKEN, "ctl-audit-observed");

        mockMvc.perform(get("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/secrets")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk());
        mockMvc.perform(put("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validJson("ctl-audit-renamed")))
                .andExpect(status().isOk());
        mockMvc.perform(delete("/api/secrets/" + id)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isNoContent());

        List<AuditLog> forSecret = auditLogRepository.findAll().stream()
                .filter(entry -> id.equals(entry.getResourceId()))
                .toList();
        assertEquals(4, forSecret.size(),
                "create, read, update and delete must each produce exactly one audit record");
        assertEquals(Set.of("SECRET_CREATE", "SECRET_READ", "SECRET_UPDATE", "SECRET_DELETE"),
                forSecret.stream().map(AuditLog::getAction).collect(Collectors.toSet()),
                "each CRUD action must be recorded with its own action name");

        String aliceUserId = userRepository.findByKeycloakId(aliceKeycloakId).orElseThrow()
                .getId().toString();
        for (AuditLog entry : forSecret) {
            assertEquals("SECRET", entry.getResourceType());
            assertEquals(aliceUserId, entry.getActor().getId().toString(),
                    "the authenticated actor must be recorded");
            assertNotNull(entry.getTimestamp(), "each record must carry its event timestamp");
            assertEquals(32, entry.getRecordHash().length, "hashes are raw SHA-256 bytes");
            assertEquals(32, entry.getPreviousHash().length);
            assertFalse(entry.getMetadata().contains(b64(CONTENT)), "ciphertext must never be logged");
            assertFalse(entry.getMetadata().contains(b64(WRAPPED_DEK)), "wrapped DEKs must never be logged");
        }

        List<AuditLog> listEvents = auditLogRepository.findAll().stream()
                .filter(entry -> "SECRET_LIST".equals(entry.getAction())
                        && entry.getActor() != null
                        && aliceUserId.equals(entry.getActor().getId().toString()))
                .toList();
        assertFalse(listEvents.isEmpty(), "listing secrets must be recorded as an access event");
        assertTrue(listEvents.stream().allMatch(entry -> entry.getMetadata().matches("\\{\"count\":\\d+}")),
                "list metadata must only carry the secret count");

        assertTrue(auditLogService.verifyChain(), "every recorded action must form a valid hash chain");
    }
}