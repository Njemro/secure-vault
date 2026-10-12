package unibl.sni.securevault.exception;

/**
 * Thrown when a requested record does not exist. Mapped to an HTTP error
 * response by the global exception handler (added in the controller task).
 * Messages must never contain secrets or other sensitive values.
 */
public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }
}
