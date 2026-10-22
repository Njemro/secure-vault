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
import unibl.sni.securevault.dto.UserKeyRegisterRequest;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserKey;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.repository.UserKeyRepository;
import unibl.sni.securevault.repository.UserRepository;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class UserKeyControllerTests {

    private static final String ALICE_TOKEN = "test-token-userkey-alice";
    private static final String BOB_TOKEN = "test-token-userkey-bob";
    private static final String INVALID_TOKEN = "invalid-token";

    private static final byte[] PUBLIC_KEY = {1, 2, 3, 4, 5};
    private static final byte[] ENCRYPTED_PRIVATE_KEY = {9, 8, 7, 6, 5, 4, 3, 2, 1};
    private static final byte[] PRIVATE_KEY_IV = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserKeyRepository userKeyRepository;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    private String aliceKeycloakId;
    private String bobKeycloakId;
    private UUID aliceUserId;
    private UUID bobUserId;

    @BeforeEach
    void seedUsersAndStubDecoder() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        aliceKeycloakId = "kc-userkey-a-" + suffix;
        bobKeycloakId = "kc-userkey-b-" + suffix;

        User alice = userRepository.save(new User(aliceKeycloakId,
                "userkey-alice-" + suffix, Role.DEVELOPER, UserStatus.ACTIVE));
        User bob = userRepository.save(new User(bobKeycloakId,
                "userkey-bob-" + suffix, Role.DEVELOPER, UserStatus.ACTIVE));

        aliceUserId = alice.getId();
        bobUserId = bob.getId();

        Mockito.lenient().when(jwtDecoder.decode(anyString())).thenAnswer(invocation -> {
            String token = invocation.getArgument(0);
            return switch (token) {
                case ALICE_TOKEN -> jwtWithSubject(aliceKeycloakId);
                case BOB_TOKEN -> jwtWithSubject(bobKeycloakId);
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

    private static UserKeyRegisterRequest validRequest() {
        return new UserKeyRegisterRequest(
                PUBLIC_KEY, ENCRYPTED_PRIVATE_KEY, PRIVATE_KEY_IV,
                "PBKDF2-HMAC-SHA-256", "{\"iterations\":100000}");
    }

    private String registerKeysJson() throws Exception {
        return objectMapper.writeValueAsString(validRequest());
    }

    // ------------------------------------------------------------------
    // PUT /api/users/keys
    // ------------------------------------------------------------------

    @Test
    void registerKeysAssociatesMaterialWithJwtSubjectUser() throws Exception {
        mockMvc.perform(put("/api/users/keys")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerKeysJson()))
                .andExpect(status().isOk());

        var key = userKeyRepository.findByUserId(aliceUserId).orElseThrow();
        assertNotNull(key.getId());
        assertEquals(PUBLIC_KEY.length, key.getPublicKey().length);
        assertEquals(ENCRYPTED_PRIVATE_KEY.length, key.getEncryptedPrivateKey().length);
        assertEquals(PRIVATE_KEY_IV.length, key.getPrivateKeyIv().length);
    }

    @Test
    void registerKeysRejectsEmptyPublicKey() throws Exception {
        UserKeyRegisterRequest request = new UserKeyRegisterRequest(
                new byte[0], ENCRYPTED_PRIVATE_KEY, PRIVATE_KEY_IV,
                "PBKDF2-HMAC-SHA-256", "{}");
        String json = objectMapper.writeValueAsString(request);

        mockMvc.perform(put("/api/users/keys")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest());
    }

    @Test
    void registerKeysRejectsBlankKdfAlgorithm() throws Exception {
        UserKeyRegisterRequest request = new UserKeyRegisterRequest(
                PUBLIC_KEY, ENCRYPTED_PRIVATE_KEY, PRIVATE_KEY_IV,
                "  ", "{}");
        String json = objectMapper.writeValueAsString(request);

        mockMvc.perform(put("/api/users/keys")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest());
    }

    @Test
    void registerKeysWithoutAuthenticationReturns401() throws Exception {
        mockMvc.perform(put("/api/users/keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerKeysJson()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registerKeysWithInvalidBearerReturns401() throws Exception {
        mockMvc.perform(put("/api/users/keys")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + INVALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerKeysJson()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registerKeysForUnprovisionedSubjectReturns404() throws Exception {
        String unknownKeycloakId = "kc-unknown-" + UUID.randomUUID();
        Mockito.lenient().when(jwtDecoder.decode(ALICE_TOKEN))
                .thenReturn(jwtWithSubject(unknownKeycloakId));

        mockMvc.perform(put("/api/users/keys")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerKeysJson()))
                .andExpect(status().isNotFound());
    }

    // ------------------------------------------------------------------
    // GET /api/users/me/keys
    // ------------------------------------------------------------------

    @Test
    void getMyKeysReturnsOwnKeyMaterial() throws Exception {
        userKeyRepository.save(new UserKey(
                userRepository.findByKeycloakId(aliceKeycloakId).orElseThrow(),
                PUBLIC_KEY, ENCRYPTED_PRIVATE_KEY, PRIVATE_KEY_IV,
                "PBKDF2-HMAC-SHA-256", "{\"iterations\":100000}"));

        mockMvc.perform(get("/api/users/me/keys")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(aliceUserId.toString()))
                .andExpect(jsonPath("$.publicKey").value(b64(PUBLIC_KEY)));
    }

    @Test
    void getMyKeysWithoutKeyRecordReturns404() throws Exception {
        // Bob has a user record but no key record.
        mockMvc.perform(get("/api/users/me/keys")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + BOB_TOKEN))
                .andExpect(status().isNotFound());
    }

    // ------------------------------------------------------------------
    // GET /api/users/{id}/public-key
    // ------------------------------------------------------------------

    @Test
    void getPublicKeyReturnsPublicKeyOnly() throws Exception {
        userKeyRepository.save(new UserKey(
                userRepository.findByKeycloakId(aliceKeycloakId).orElseThrow(),
                PUBLIC_KEY, ENCRYPTED_PRIVATE_KEY, PRIVATE_KEY_IV,
                "PBKDF2-HMAC-SHA-256", "{\"iterations\":100000}"));

        User alice = userRepository.findByKeycloakId(aliceKeycloakId).orElseThrow();

        mockMvc.perform(get("/api/users/" + alice.getId() + "/public-key")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(alice.getId().toString()))
                .andExpect(jsonPath("$.username").value(alice.getUsername()))
                .andExpect(jsonPath("$.publicKey").value(b64(PUBLIC_KEY)));
    }

    @Test
    void getPublicKeyNeverExposesEncryptedPrivateKey() throws Exception {
        userKeyRepository.save(new UserKey(
                userRepository.findByKeycloakId(aliceKeycloakId).orElseThrow(),
                PUBLIC_KEY, ENCRYPTED_PRIVATE_KEY, PRIVATE_KEY_IV,
                "PBKDF2-HMAC-SHA-256", "{\"iterations\":100000}"));

        User alice = userRepository.findByKeycloakId(aliceKeycloakId).orElseThrow();

        String response = mockMvc.perform(get("/api/users/" + alice.getId() + "/public-key")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertTrue(response.contains("publicKey"), "response must contain publicKey");
        assertFalse(response.contains("encryptedPrivateKey"),
                "encrypted private key must never be exposed");
    }

    @Test
    void getPublicKeyUnknownUserReturns404() throws Exception {
        mockMvc.perform(get("/api/users/" + UUID.randomUUID() + "/public-key")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isNotFound());
    }

    @Test
    void getPublicKeyUserWithoutKeyRecordReturns404() throws Exception {
        // Bob has a user record but no key record.
        mockMvc.perform(get("/api/users/" + bobUserId + "/public-key")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + ALICE_TOKEN))
                .andExpect(status().isNotFound());
    }
}