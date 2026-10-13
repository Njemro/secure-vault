package unibl.sni.securevault.dto;

import java.time.LocalDateTime;

/**
 * Consistent JSON error response returned by the global exception handler.
 * It only carries safe, generic information: never stack traces, exception
 * class names, SQL, configuration, request bodies, or any secret,
 * credential, token or key material.
 */
public record ErrorResponse(
        LocalDateTime timestamp,
        int status,
        String error,
        String message,
        String path) {
}
