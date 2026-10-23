package unibl.sni.securevault.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import unibl.sni.securevault.dto.LoginRequest;
import unibl.sni.securevault.dto.LoginResponse;
import unibl.sni.securevault.dto.MfaVerifyRequest;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.service.AuthService;

import java.util.UUID;

/**
 * Authentication endpoints: login (first factor), MFA verification (second
 * factor), logout, and current-user profile. The vault master password is
 * never part of any request or response (AGENTS.md section 8).
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * First factor: validate username/password against Keycloak. Returns an
     * access token if MFA is not required, or an MFA-challenge response if it
     * is. The client must complete {@code /api/auth/mfa/verify} before
     * accessing protected resources when {@code mfaRequired} is true.
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        String sourceIp = httpRequest.getRemoteAddr();
        LoginResponse response = authService.login(request.username(), request.password(), sourceIp);
        if (response.accessToken() == null && response.mfaRequired()) {
            return ResponseEntity.status(HttpStatus.OK).body(response);
        }
        return ResponseEntity.ok(response);
    }

    /**
     * Second factor: verify a TOTP code and receive a full access token.
     * Only valid after a successful first-factor login that returned
     * {@code mfaRequired = true}.
     */
    @PostMapping("/mfa/verify")
    public ResponseEntity<LoginResponse> verifyMfa(
            @RequestBody MfaVerifyRequest request,
            HttpServletRequest httpRequest) {
        String sourceIp = httpRequest.getRemoteAddr();
        // The temporary token would normally be passed via a header or cookie.
        // For simplicity, the client presents it as the "code" field is the
        // TOTP code; the temp token is expected in the Authorization header.
        String tempToken = extractTempToken(httpRequest);
        LoginResponse response = authService.verifyMfa(tempToken, request.code(), sourceIp);
        return ResponseEntity.ok(response);
    }

    /**
     * Returns the authenticated user's profile and MFA status.
     */
    // @GetMapping("/me") - temporarily disabled pending JWT principal resolver
    // public ResponseEntity<UserProfileResponse> me(@AuthenticationPrincipal Jwt jwt) { ... }

    private String extractTempToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}
