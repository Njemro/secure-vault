/**
 * One exception class per error case, plus GlobalExceptionHandler
 * ({@code @RestControllerAdvice}) that maps exceptions to HTTP responses.
 * Error messages must never reveal secrets or internal stack traces.
 */
package unibl.sni.securevault.exception;
