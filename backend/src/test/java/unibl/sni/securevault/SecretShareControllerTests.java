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
import unibl.sni.securevault.repository.UserKeyRepository;
import unibl.sni.securevault.repository.UserRepository;
import unibl.sni.securevault.service.AuditLogService;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecretShareControllerTests {

    private static final String ALICE_TOKEN = "test-token-alice-share";
    private static final String BOB_TOKEN = "test-token-bob-share";
    private static final String CHARLIE_TOKEN = "test-token-charlie-share";

    private static final byte[] CONTENT = {10, 20, 30, 40, 50};
    private static final byte[] WRAPPED_DEK = {1, 2, 3, 4, 5, 6, 7, 8};
    private static final byte[] CONTENT_IV = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
    private static final byte[] DEK_IV = {8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8};
    private static final byte[] BOB_WRAPPED_DEK = {11, 12, 13, 14};
    private static final byte[] PUBLIC_KEY = {21, 22, 23, 24, 25};

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private UserKeyRepository userKeyRepository;
    @Autowired private AuditLogRepository auditLogRepository;
    @Autowired private AuditLogService auditLogService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    private String aliceKeycloakId;
    private String bobKeycloakId;
    private String charlieKeycloakId;

    @BeforeEach
    void seedUsersAndStubDecoder() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        aliceKeycloakId = "kc-share-a-" + suffix;
        bobKeycloakId = "kc-share-b-" + suffix;
        charlieKeycloakId = "kc-share-c-" + suffix;

        User alice = userRepository.save(new User(aliceKeycloakId, "share-alice-" + suffix,
                Role.TEAM_LEAD, UserStatus.ACTIVE));
        User bob = userRepository.save(new User(bobKeycloakId, "share-bob-" + suffix,
                Role.DEVELOPER, UserStatus.ACTIVE));
        User charlie = userRepository.save(new User(charlieKeycloakId, "share-charlie-" + suffix,
                Role.DEVELOPER, UserStatus.ACTIVE));

        userKeyRepository.save(new unibl.sni.securevault.entity.UserKey(
                alice, PUBLIC_KEY, new byte[16], new byte[12], "RSA-OAEP", "{}"));
        userKeyRepository.save(new unibl.sni.securevault.entity.UserKey(
                bob, PUBLIC_KEY, new byte[16], new byte[12], "RSA-OAEP", "{}"));
        userKeyRepository.save(new unibl.sni.securevault.entity.UserKey(
                charlie, PUBLIC_KEY, new byte[16], new byte[12], "RSA-OAEP", "{}"));

        Mockito.lenient().when(jwtDecoder.decode(anyString())).thenAnswer(invocation -> {
            String token = invocation.getArgument(0);
            return switch (token) {
                case ALICE_TOKEN -> jwtWithSubject(aliceKeycloakId);
                case BOB_TOKEN -> jwtWithSubject(bobKeycloakId);
                case CHARLIE_TOKEN -> jwtWithSubject(charlieKeycloakId);
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

    private String shareJson(UUID recipientId, byte[] encryptedDek) {
        return """
            {"recipients":[{"recipientId":"%s","encryptedDek":"%s"}]}
            """.formatted(recipientId, b64(encryptedDek));
    }

    private UUID aliceUserId() {
        return userRepository.findByKeycloakId(aliceKeycloakId).orElseThrow().getId();
    }

    private UUID bobUserId() {
        return userRepository.findByKeycloakId(bobKeycloakId).orElseThrow().getId();
    }

    private UUID charlieUserId() {
        return userRepository.findByKeycloakId(charlieKeycloakId).orElseThrow().getId();
    }

    // ------------------------------------------------------------------
    // Authentication
    // ------------------------------------------------------------------

    @Test
    void unauthenticatedShareIsRejectedWith401() throws Exception {
        mockMvc.perform(post("/api/secrets/" + UUID.randomUUID() + "/shares")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(UUID.randomUUID(), WRAPPED_DEK)))
                .andExpect(status().isUnauthorized());
    }

    // ------------------------------------------------------------------
    // Share: authorized Team Lead owner
    // ------------------------------------------------------------------

    @Test
    void teamLeadOwnerCanShareWithDeveloper() throws Exception {
        String secretId = createSecret(ALICE_TOKEN, "share-tsl-authorized");

        mockMvc.perform(post("/api/secrets/" + secretId + "/shares")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(bobUserId(), BOB_WRAPPED_DEK)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$[0].secretId").value(secretId))
                .andExpect(jsonPath("$[0].recipientId").isNotEmpty())
                .andExpect(jsonPath("$[0].encryptedDek").value(b64(BOB_WRAPPED_DEK)));
    }

    @Test
    void shareIsRecordedInAuditChain() throws Exception {
        String secretId = createSecret(ALICE_TOKEN, "share-tsl-audit");

        mockMvc.perform(post("/api/secrets/" + secretId + "/shares")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(bobUserId(), BOB_WRAPPED_DEK)))
                .andExpect(status().isCreated());

        String aliceUserId = aliceUserId().toString();

        List<AuditLog> shareEvents = auditLogRepository.findAll().stream()
                .filter(entry -> "SECRET_SHARE".equals(entry.getAction())
                        && secretId.equals(entry.getResourceId())
                        && aliceUserId.equals(entry.getActor().getId().toString()))
                .toList();
        assertEquals(1, shareEvents.size(), "exactly one SECRET_SHARE audit record");
        assertEquals("SECRET", shareEvents.get(0).getResourceType());
        assertNotNull(shareEvents.get(0).getMetadata());
        assertFalse(shareEvents.get(0).getMetadata().contains(b64(CONTENT)),
                "ciphertext must never be logged");
        assertFalse(shareEvents.get(0).getMetadata().contains(b64(BOB_WRAPPED_DEK)),
                "wrapped DEK must never be logged");
        assertEquals(32, shareEvents.get(0).getRecordHash().length);
        assertEquals(32, shareEvents.get(0).getPreviousHash().length);

        assertTrue(auditLogService.verifyChain(), "hash chain must verify after share");
    }

    // ------------------------------------------------------------------
    // Share: authorization failures
    // ------------------------------------------------------------------

    @Test
    void developerCannotShareSecret() throws Exception {
        String secretId = createSecret(BOB_TOKEN, "share-dev-cannot-share");

        mockMvc.perform(post("/api/secrets/" + secretId + "/shares")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(charlieUserId(), BOB_WRAPPED_DEK)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void nonTeamLeadCannotShare() throws Exception {
        String secretId = createSecret(ALICE_TOKEN, "share-non-team-lead");

        mockMvc.perform(post("/api/secrets/" + secretId + "/shares")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(charlieUserId(), BOB_WRAPPED_DEK)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shareMissingSecretReturns404() throws Exception {
        mockMvc.perform(post("/api/secrets/" + UUID.randomUUID() + "/shares")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(bobUserId(), BOB_WRAPPED_DEK)))
                .andExpect(status().isNotFound());
    }

    // ------------------------------------------------------------------
    // List shared secrets: recipient-only view
    // ------------------------------------------------------------------

    @Test
    void recipientSeesOnlyOwnSharedSecrets() throws Exception {
        String secretId = createSecret(ALICE_TOKEN, "share-list-visible");

        mockMvc.perform(post("/api/secrets/" + secretId + "/shares")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(bobUserId(), BOB_WRAPPED_DEK)))
                .andExpect(status().isCreated());

        MvcResult bobResult = mockMvc.perform(get("/api/secrets/shared")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN))
                .andExpect(status().isOk())
                .andReturn();
        List<Map<String, Object>> bobList = objectMapper.readValue(
                bobResult.getResponse().getContentAsString(), List.class);
        assertEquals(1, bobList.size(), "bob must see exactly one shared secret");
        assertEquals(secretId, bobList.get(0).get("id"));

        MvcResult charlieResult = mockMvc.perform(get("/api/secrets/shared")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + CHARLIE_TOKEN))
                .andExpect(status().isOk())
                .andReturn();
        List<Map<String, Object>> charlieList = objectMapper.readValue(
                charlieResult.getResponse().getContentAsString(), List.class);
        assertTrue(charlieList.isEmpty(), "charlie must see no shared secrets");
    }

    @Test
    void listSharedIsRecordedInAuditChain() throws Exception {
        String secretId = createSecret(ALICE_TOKEN, "share-list-audit");

        mockMvc.perform(post("/api/secrets/" + secretId + "/shares")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(bobUserId(), BOB_WRAPPED_DEK)))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/api/secrets/shared")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN))
                .andExpect(status().isOk());

        String bobUserId = userRepository.findByKeycloakId(bobKeycloakId).orElseThrow()
                .getId().toString();

        List<AuditLog> listEvents = auditLogRepository.findAll().stream()
                .filter(entry -> "SHARED_SECRET_LIST".equals(entry.getAction())
                        && bobUserId.equals(entry.getActor().getId().toString()))
                .toList();
        assertFalse(listEvents.isEmpty(), "shared secret list must be audited");
        assertTrue(listEvents.stream().allMatch(entry -> entry.getMetadata().matches(
                "\\{\"count\":\\d+}")), "list metadata must only carry the count");

        assertTrue(auditLogService.verifyChain(), "hash chain must verify after list");
    }

    // ------------------------------------------------------------------
    // Read shared secret: recipient gets ciphertext + own wrapped DEK
    // ------------------------------------------------------------------

    @Test
    void recipientRetrievesSharedSecretWithWrappedDek() throws Exception {
        String secretId = createSecret(ALICE_TOKEN, "share-read-roundtrip");

        mockMvc.perform(post("/api/secrets/" + secretId + "/shares")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(bobUserId(), BOB_WRAPPED_DEK)))
                .andExpect(status().isCreated());

        MvcResult result = mockMvc.perform(get("/api/secrets/shared/" + secretId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(secretId))
                .andExpect(jsonPath("$.encryptedValue").value(b64(CONTENT)))
                .andExpect(jsonPath("$.contentIv").value(b64(CONTENT_IV)))
                .andExpect(jsonPath("$.encryptionAlgorithm").value("AES-256-GCM"))
                .andExpect(jsonPath("$.recipientEncryptedDek").value(b64(BOB_WRAPPED_DEK)))
                .andReturn();

        String body = result.getResponse().getContentAsString();
        UUID aliceUserId = userRepository.findByKeycloakId(aliceKeycloakId).orElseThrow().getId();
        assertTrue(body.contains("\"ownerId\":\"" + aliceUserId + "\""),
                "shared secret response should carry the owner id");
    }

    @Test
    void nonRecipientCannotReadSharedSecret() throws Exception {
        String secretId = createSecret(ALICE_TOKEN, "share-read-blocked");

        mockMvc.perform(post("/api/secrets/" + secretId + "/shares")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(bobUserId(), BOB_WRAPPED_DEK)))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/api/secrets/shared/" + secretId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + CHARLIE_TOKEN))
                .andExpect(status().isNotFound());
    }

    @Test
    void readSharedSecretIsRecordedInAuditChain() throws Exception {
        String secretId = createSecret(ALICE_TOKEN, "share-read-audit");

        mockMvc.perform(post("/api/secrets/" + secretId + "/shares")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(bobUserId(), BOB_WRAPPED_DEK)))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/api/secrets/shared/" + secretId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN))
                .andExpect(status().isOk());

        String bobUserId = userRepository.findByKeycloakId(bobKeycloakId).orElseThrow()
                .getId().toString();

        List<AuditLog> readEvents = auditLogRepository.findAll().stream()
                .filter(entry -> "SHARED_SECRET_READ".equals(entry.getAction())
                        && secretId.equals(entry.getResourceId())
                        && bobUserId.equals(entry.getActor().getId().toString()))
                .toList();
        assertEquals(1, readEvents.size(), "exactly one SHARED_SECRET_READ audit record");
        assertEquals("{}", readEvents.get(0).getMetadata());

        assertTrue(auditLogService.verifyChain(), "hash chain must verify after read");
    }

    // ------------------------------------------------------------------
    // Original secret remains unmodified by sharing
    // ------------------------------------------------------------------

    @Test
    void originalSecretIsUnmodifiedBySharing() throws Exception {
        String secretId = createSecret(ALICE_TOKEN, "share-unmodified");

        MvcResult before = mockMvc.perform(get("/api/secrets/" + secretId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk())
                .andReturn();
        String beforeBody = before.getResponse().getContentAsString();

        mockMvc.perform(post("/api/secrets/" + secretId + "/shares")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(shareJson(bobUserId(), BOB_WRAPPED_DEK)))
                .andExpect(status().isCreated());

        MvcResult after = mockMvc.perform(get("/api/secrets/" + secretId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk())
                .andReturn();
        String afterBody = after.getResponse().getContentAsString();

        assertEquals(beforeBody, afterBody, "original secret ciphertext must be unchanged");
    }

    // ------------------------------------------------------------------
    // Public key endpoint
    // ------------------------------------------------------------------

    @Test
    void publicKeyEndpointReturnsPublicKeyOnly() throws Exception {
        User alice = userRepository.findByKeycloakId(aliceKeycloakId).orElseThrow();

        mockMvc.perform(get("/api/users/" + alice.getId() + "/public-key")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(alice.getId().toString()))
                .andExpect(jsonPath("$.username").value(alice.getUsername()))
                .andExpect(jsonPath("$.publicKey").value(b64(PUBLIC_KEY)));
    }

    @Test
    void publicKeyEndpointMissingUserReturns404() throws Exception {
        mockMvc.perform(get("/api/users/" + UUID.randomUUID() + "/public-key")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isNotFound());
    }

    @Test
    void publicKeyEndpointMissingKeyRecordReturns404() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        User noKeyUser = userRepository.save(new User("kc-share-nokey2-" + suffix,
                "share-nokey2-" + suffix, Role.DEVELOPER, UserStatus.ACTIVE));

        mockMvc.perform(get("/api/users/" + noKeyUser.getId() + "/public-key")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isNotFound());
    }
}