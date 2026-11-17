package unibl.sni.securevault.controller;

import unibl.sni.securevault.dto.HoneypotDemoRequest;
import unibl.sni.securevault.dto.HoneypotDemoStatusResponse;
import unibl.sni.securevault.entity.HoneypotDemoState;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.repository.UserRepository;
import unibl.sni.securevault.service.HoneypotDemoService;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/honeypot/demo")
public class HoneypotDemoController {

    private final HoneypotDemoService demoService;
    private final UserRepository userRepository;

    public HoneypotDemoController(
            HoneypotDemoService demoService,
            UserRepository userRepository
    ) {
        this.demoService = demoService;
        this.userRepository = userRepository;
    }

    @GetMapping("/status")
    public HoneypotDemoStatusResponse status(
            @AuthenticationPrincipal Jwt jwt
    ) {
        requireAdmin(jwt);

        HoneypotDemoState state = demoService.getState();

        return new HoneypotDemoStatusResponse(
                state.isEnabled(),
                state.getEnabledUntil(),
                state.getEnabledBy() == null
                        ? null
                        : state.getEnabledBy().getUsername()
        );
    }

    @PostMapping("/enable")
    public HoneypotDemoStatusResponse enable(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody HoneypotDemoRequest request
    ) {
        User admin = requireAdmin(jwt);

        demoService.enable(admin, request.durationMinutes());

        HoneypotDemoState state = demoService.getState();

        return new HoneypotDemoStatusResponse(
                state.isEnabled(),
                state.getEnabledUntil(),
                state.getEnabledBy() == null
                        ? null
                        : state.getEnabledBy().getUsername()
        );
    }

    @PostMapping("/disable")
    public ResponseEntity<Void> disable(
            @AuthenticationPrincipal Jwt jwt
    ) {
        requireAdmin(jwt);
        demoService.disable();
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/search")
    public ResponseEntity<String> search(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam String term,
            HttpServletRequest request
    ) {
        User currentUser = requireCurrentUser(jwt);

        String result = demoService.runVulnerableSearch(
                currentUser,
                term,
                request.getRemoteAddr()
        );

        return ResponseEntity.ok(result);
    }

    private User requireAdmin(Jwt jwt) {
        User user = requireCurrentUser(jwt);

        if (!"ADMIN".equals(user.getRole().name())) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.FORBIDDEN,
                    "Administrator access required"
            );
        }

        return user;
    }

    private User requireCurrentUser(Jwt jwt) {
        return userRepository.findByKeycloakId(jwt.getSubject())
                .filter(user -> "ACTIVE".equals(user.getStatus().name()))
                .orElseThrow(() ->
                        new org.springframework.web.server.ResponseStatusException(
                                org.springframework.http.HttpStatus.FORBIDDEN,
                                "Account is not active"
                        )
                );
    }
}
