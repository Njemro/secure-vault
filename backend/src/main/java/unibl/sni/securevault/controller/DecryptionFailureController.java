package unibl.sni.securevault.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import unibl.sni.securevault.entity.SecurityEvent;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.repository.SecurityEventRepository;
import unibl.sni.securevault.service.UserService;

@RestController
@RequestMapping("/api/security-events")
public class DecryptionFailureController {

    private final SecurityEventRepository securityEventRepository;
    private final UserService userService;

    public DecryptionFailureController(
            SecurityEventRepository securityEventRepository,
            UserService userService) {
        this.securityEventRepository = securityEventRepository;
        this.userService = userService;
    }

    /**
     * The browser reports only the fact of a failed cryptographic operation.
     * No master password, key, plaintext, ciphertext or secret identifier is sent.
     */
    @PostMapping("/decryption-failure")
    public ResponseEntity<Void> reportDecryptionFailure(
            Authentication authentication,
            HttpServletRequest request) {
        if (!(authentication instanceof JwtAuthenticationToken jwtAuthentication)) {
            return ResponseEntity.status(401).build();
        }

        User user = userService.findByKeycloakId(jwtAuthentication.getToken().getSubject())
                .orElseThrow(() -> new ResourceNotFoundException("User not found."));

        String sourceIp = request.getHeader("X-SecureVault-Client-IP");
        if (sourceIp == null || sourceIp.isBlank()) {
            sourceIp = request.getRemoteAddr();
        }

        securityEventRepository.save(new SecurityEvent(
                user,
                "DECRYPTION_FAILURE",
                sourceIp,
                "{\"source\":\"BROWSER_CRYPTO\",\"details\":\"No secret data recorded\"}"));

        return ResponseEntity.accepted().build();
    }
}
