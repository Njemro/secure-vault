package unibl.sni.securevault;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import unibl.sni.securevault.dto.RecipientShareInput;
import unibl.sni.securevault.dto.SecretCreateRequest;
import unibl.sni.securevault.dto.SecretShareCreateRequest;
import unibl.sni.securevault.dto.SecurityPolicyRequest;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DTO validation tests using Bean Validation directly (no Spring context and
 * therefore no database of any kind). Covers invalid policy values, empty
 * encrypted payloads and malformed multi-recipient share requests.
 */
class DtoValidationTests {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void createValidator() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void closeValidator() {
        factory.close();
    }

    private static <T> Set<ConstraintViolation<T>> validate(T dto) {
        return validator.validate(dto);
    }

    private static <T> boolean hasViolationAt(Set<ConstraintViolation<T>> violations, String pathPart) {
        return violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().contains(pathPart));
    }

    private static <T> String describe(Set<ConstraintViolation<T>> violations) {
        StringBuilder sb = new StringBuilder();
        violations.forEach(v -> sb.append(v.getPropertyPath()).append(": ").append(v.getMessage())
                .append(" | "));
        return sb.toString();
    }

    @Test
    void policyRequestEnforcesSchemaConstraints() {
        assertEquals(0, validate(new SecurityPolicyRequest(10, 30, 60)).size(),
                "valid policy must produce no violations");

        Set<ConstraintViolation<SecurityPolicyRequest>> tooShort =
                validate(new SecurityPolicyRequest(7, 30, 60));
        assertTrue(hasViolationAt(tooShort, "minMasterPasswordLength"), describe(tooShort));

        Set<ConstraintViolation<SecurityPolicyRequest>> zeroRotation =
                validate(new SecurityPolicyRequest(8, 0, 60));
        assertTrue(hasViolationAt(zeroRotation, "secretRotationIntervalDays"), describe(zeroRotation));

        Set<ConstraintViolation<SecurityPolicyRequest>> zeroSession =
                validate(new SecurityPolicyRequest(8, 30, 0));
        assertTrue(hasViolationAt(zeroSession, "sessionDurationMinutes"), describe(zeroSession));
    }

    @Test
    void secretCreateRequestRejectsBlankAndEmptyPayloads() {
        assertEquals(0, validate(validSecretRequest()).size(),
                "valid secret request must produce no violations");

        Set<ConstraintViolation<SecretCreateRequest>> blankName =
                validate(new SecretCreateRequest("  ", null, new byte[16], new byte[16],
                        new byte[12], new byte[12], "AES-256-GCM"));
        assertTrue(hasViolationAt(blankName, "name"), describe(blankName));

        Set<ConstraintViolation<SecretCreateRequest>> emptyContent =
                validate(new SecretCreateRequest("api-key", null, new byte[0], new byte[16],
                        new byte[12], new byte[12], "AES-256-GCM"));
        assertTrue(hasViolationAt(emptyContent, "encryptedValue"), describe(emptyContent));

        Set<ConstraintViolation<SecretCreateRequest>> emptyDek =
                validate(new SecretCreateRequest("api-key", null, new byte[16], new byte[0],
                        new byte[12], new byte[12], "AES-256-GCM"));
        assertTrue(hasViolationAt(emptyDek, "encryptedDek"), describe(emptyDek));

        Set<ConstraintViolation<SecretCreateRequest>> nullIv =
                validate(new SecretCreateRequest("api-key", null, new byte[16], new byte[16],
                        new byte[12], null, "AES-256-GCM"));
        assertTrue(hasViolationAt(nullIv, "dekIv"), describe(nullIv));

        Set<ConstraintViolation<SecretCreateRequest>> blankAlgorithm =
                validate(new SecretCreateRequest("api-key", null, new byte[16], new byte[16],
                        new byte[12], new byte[12], " "));
        assertTrue(hasViolationAt(blankAlgorithm, "encryptionAlgorithm"), describe(blankAlgorithm));
    }

    private static SecretCreateRequest validSecretRequest() {
        return new SecretCreateRequest("api-key", "demo", new byte[16], new byte[16],
                new byte[12], new byte[12], "AES-256-GCM");
    }

    @Test
    void shareRequestAcceptsValidRecipientList() {
        var request = new SecretShareCreateRequest(List.of(
                new RecipientShareInput(UUID.randomUUID(), new byte[256]),
                new RecipientShareInput(UUID.randomUUID(), new byte[256])));
        assertEquals(0, validate(request).size(),
                "valid two-recipient share must produce no violations");
    }

    @Test
    void shareRequestRequiresAtLeastOneRecipient() {
        Set<ConstraintViolation<SecretShareCreateRequest>> nullList =
                validate(new SecretShareCreateRequest(null));
        assertTrue(hasViolationAt(nullList, "recipients"), describe(nullList));

        Set<ConstraintViolation<SecretShareCreateRequest>> emptyList =
                validate(new SecretShareCreateRequest(List.of()));
        assertTrue(hasViolationAt(emptyList, "recipients"), describe(emptyList));
    }

    @Test
    void shareRequestRejectsMalformedRecipientEntries() {
        Set<ConstraintViolation<SecretShareCreateRequest>> nullRecipientId =
                validate(new SecretShareCreateRequest(
                        List.of(new RecipientShareInput(null, new byte[256]))));
        assertTrue(hasViolationAt(nullRecipientId, "recipientId"), describe(nullRecipientId));

        Set<ConstraintViolation<SecretShareCreateRequest>> emptyEncryptedDek =
                validate(new SecretShareCreateRequest(
                        List.of(new RecipientShareInput(UUID.randomUUID(), new byte[0]))));
        assertTrue(hasViolationAt(emptyEncryptedDek, "encryptedDek"), describe(emptyEncryptedDek));

        // Cascade: one bad entry inside an otherwise valid list is reported at
        // its index, proving @Valid reaches the nested entries.
        Set<ConstraintViolation<SecretShareCreateRequest>> nested =
                validate(new SecretShareCreateRequest(List.of(
                        new RecipientShareInput(UUID.randomUUID(), new byte[256]),
                        new RecipientShareInput(UUID.randomUUID(), null))));
        assertTrue(nested.stream().anyMatch(v ->
                        v.getPropertyPath().toString().contains("recipients[1].encryptedDek")),
                describe(nested));
    }
}

