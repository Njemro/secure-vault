package unibl.sni.securevault.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import unibl.sni.securevault.dto.ErrorResponse;

import java.time.LocalDateTime;
import java.util.stream.Collectors;

/**
 * Maps service and framework exceptions to a consistent {@link ErrorResponse}
 * JSON shape. Error messages stay safe by construction: validation details
 * contain only field names and constraint messages (never rejected values or
 * request bodies), and unexpected exceptions are reduced to a generic 500
 * message - stack traces and internal details only ever reach server logs.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private static final String GENERIC_SERVER_ERROR_MESSAGE = "Internal server error";

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFound(ResourceNotFoundException ex,
                                                                HttpServletRequest request) {
        return respond(HttpStatus.NOT_FOUND, ex, request);
    }

    @ExceptionHandler(InvalidOperationRequestException.class)
    public ResponseEntity<ErrorResponse> handleInvalidOperationRequest(InvalidOperationRequestException ex,
                                                                       HttpServletRequest request) {
        return respond(HttpStatus.BAD_REQUEST, ex, request);
    }

    /**
     * Bean validation failures. Only field names and constraint messages are
     * exposed - rejected values are deliberately omitted because they may
     * contain encrypted payloads or other sensitive input.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                      HttpServletRequest request) {
        String details = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));
        if (details.isBlank()) {
            details = "Validation failed";
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(LocalDateTime.now(), HttpStatus.BAD_REQUEST.value(),
                        HttpStatus.BAD_REQUEST.getReasonPhrase(), details, request.getRequestURI()));
    }

    /** Anything unhandled: generic message only, never exception internals. */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception ex, HttpServletRequest request) {
        logger.error("Unhandled exception while processing {} {}",
                request.getMethod(), request.getRequestURI(), ex);
        // Deliberately does not use respond(): unexpected exception messages may
        // contain SQL, configuration, stack traces or connection strings, which
        // must never reach the client. Full detail only goes to server logs above.
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse(LocalDateTime.now(), HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(),
                        GENERIC_SERVER_ERROR_MESSAGE, request.getRequestURI()));
    }

    private static ResponseEntity<ErrorResponse> respond(HttpStatus status, Exception ex,
                                                         HttpServletRequest request) {
        String message = ex.getMessage() != null && !ex.getMessage().isBlank()
                ? ex.getMessage()
                : status.getReasonPhrase();
        return ResponseEntity.status(status)
                .body(new ErrorResponse(LocalDateTime.now(), status.value(),
                        status.getReasonPhrase(), message, request.getRequestURI()));
    }
}
