package unibl.sni.securevault.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import unibl.sni.securevault.dto.MfaEnrollResponse;
import unibl.sni.securevault.dto.MfaStatusResponse;
import unibl.sni.securevault.dto.MfaVerifyRequest;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.service.MfaService;
import unibl.sni.securevault.service.UserService;

import java.util.UUID;

/**
 * Multi-factor authentication (TOTP) management: enrollment, status, and
 * disable. All endpoints require an authenticated session.
 * <p>TOTP secrets and verification codes are never logged.
 */
@RestController
@RequestMapping("/api/auth/mfa")
public class MfaController {

    private final MfaService mfaService;
    private final UserService userService;

    public MfaController(MfaService mfaService, UserService userService) {
        this.mfaService = mfaService;
        this.userService = userService;
    }

    /**
     * Returns the current user's MFA enrollment and enforcement status.
     */
    @GetMapping("/status")
    public ResponseEntity<MfaStatusResponse> status(@AuthenticationPrincipal Jwt jwt) {
        UUID userId = requireCurrentUserId(jwt);
        boolean enabled = mfaService.isMfaEnabled(userId);
        return ResponseEntity.ok(new MfaStatusResponse(enabled, enabled));
    }

    /**
     * Starts MFA enrollment: generates a TOTP secret and returns a provisioning
     * URI (QR code) plus the raw secret for manual entry. The secret is stored
     * in a pending state until confirmed.
     */
    @PostMapping("/enroll")
    public ResponseEntity<MfaEnrollResponse> enroll(
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {
        UUID userId = requireCurrentUserId(jwt);
        var user = userService.getById(userId);
        String username = user.getUsername();
        MfaService.MfaEnrollmentResult result = mfaService.beginEnrollment(userId, username);
        return ResponseEntity.ok(new MfaEnrollResponse(result.provisioningUri(), result.secret()));
    }

    /**
     * Confirms MFA enrollment by verifying a TOTP code. On success, MFA is
     * enabled and enforced at login.
     */
    @PostMapping("/confirm")
    public ResponseEntity<Void> confirm(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody MfaVerifyRequest request) {
        UUID userId = requireCurrentUserId(jwt);
        mfaService.confirmEnrollment(userId, request.code());
        return ResponseEntity.ok().build();
    }

    /**
     * Disables MFA. Requires a valid TOTP code as reauthentication.
     */
    @DeleteMapping("/disable")
    public ResponseEntity<Void> disable(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody MfaVerifyRequest request) {
        UUID userId = requireCurrentUserId(jwt);
        mfaService.disableMfa(userId, request.code());
        return ResponseEntity.ok().build();
    }

    private UUID requireCurrentUserId(Jwt jwt) {
        String keycloakId = jwt != null ? jwt.getSubject() : null;
        if (keycloakId == null || keycloakId.isBlank()) {
            throw new InvalidOperationRequestException("Token subject (sub) claim must not be blank");
        }
        return userService.findByKeycloakId(keycloakId)
                .map(unibl.sni.securevault.entity.User::getId)
                .orElseThrow(() -> new InvalidOperationRequestException("User is not registered in Secure Vault"));
    }
}
