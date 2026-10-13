package unibl.sni.securevault;

import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import unibl.sni.securevault.dto.ErrorResponse;
import unibl.sni.securevault.exception.GlobalExceptionHandler;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.exception.ResourceNotFoundException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the global exception handler mappings and the error
 * response shape. No controllers exist yet, so the handler methods are
 * invoked directly; no Spring context and no database are required.
 */
class GlobalExceptionHandlerTests {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    private static MockHttpServletRequest request(String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
        return request;
    }

    /** Fixture only: supplies a Method for the MethodArgumentNotValidException constructor. */
    private void fixtureMethodForMethodParameter() {
    }

    @Test
    void resourceNotFoundMapsTo404WithResponseShape() {
        ResponseEntity<ErrorResponse> response = handler.handleResourceNotFound(
                new ResourceNotFoundException("Secret not found: 123"), request("/api/secrets/123"));

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        ErrorResponse body = response.getBody();
        assertNotNull(body);
        assertNotNull(body.timestamp(), "timestamp must be set");
        assertEquals(404, body.status());
        assertEquals("Not Found", body.error());
        assertEquals("Secret not found: 123", body.message());
        assertEquals("/api/secrets/123", body.path());
    }

    @Test
    void invalidOperationMapsTo400() {
        ResponseEntity<ErrorResponse> response = handler.handleInvalidOperationRequest(
                new InvalidOperationRequestException("Requesting user does not own this secret"),
                request("/api/secrets/123/share"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ErrorResponse body = response.getBody();
        assertNotNull(body);
        assertEquals(400, body.status());
        assertEquals("Bad Request", body.error());
        assertEquals("Requesting user does not own this secret", body.message());
        assertEquals("/api/secrets/123/share", body.path());
    }

    @Test
    void validationFailureMapsTo400WithSafeFieldDetailsOnly() throws Exception {
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(
                new Object(), "secretCreateRequest");
        bindingResult.addError(new FieldError("secretCreateRequest", "name",
                "  ", true, null, null, "must not be blank"));
        bindingResult.addError(new FieldError("secretCreateRequest", "encryptedValue",
                "S3CR3T-CIPHERTEXT-DO-NOT-LEAK", true, null, null, "must not be empty"));
        MethodParameter parameter = new MethodParameter(
                GlobalExceptionHandlerTests.class.getDeclaredMethod("fixtureMethodForMethodParameter"), -1);
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(parameter, bindingResult);

        ResponseEntity<ErrorResponse> response =
                handler.handleMethodArgumentNotValid(ex, request("/api/secrets"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ErrorResponse body = response.getBody();
        assertNotNull(body);
        assertEquals(400, body.status());
        assertTrue(body.message().contains("name: must not be blank"), body.message());
        assertTrue(body.message().contains("encryptedValue: must not be empty"), body.message());
        assertFalse(body.message().contains("S3CR3T-CIPHERTEXT-DO-NOT-LEAK"),
                "rejected values must never be echoed back");
    }

    @Test
    void unexpectedExceptionMapsTo500WithGenericMessageOnly() {
        ResponseEntity<ErrorResponse> response = handler.handleUnexpected(
                new IllegalStateException("jdbc:mysql://user:password@internal/host failure"),
                request("/api/secrets"));

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        ErrorResponse body = response.getBody();
        assertNotNull(body);
        assertEquals(500, body.status());
        assertEquals("Internal Server Error", body.error());
        assertEquals("Internal server error", body.message());
        assertFalse(body.message().contains("password"),
                "internal exception details must never be exposed");
        assertFalse(body.message().contains("jdbc"), "SQL/configuration must never be exposed");
    }

    @Test
    void nullMessageFallsBackToReasonPhrase() {
        ResponseEntity<ErrorResponse> response = handler.handleResourceNotFound(
                new ResourceNotFoundException(null), request("/api/users"));

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Not Found", response.getBody().message());
    }
}
