package unibl.sni.securevault.exception;

/**
 * Thrown when an operation is invalid for the current state or caller -
 * for example a non-owner trying to read or share a secret, duplicate
 * recipients in one share request, or blank required input.
 * Messages must never contain secrets or other sensitive values.
 */
public class InvalidOperationRequestException extends RuntimeException {

    public InvalidOperationRequestException(String message) {
        super(message);
    }
}
