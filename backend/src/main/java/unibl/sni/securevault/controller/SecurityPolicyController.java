package unibl.sni.securevault.controller;

import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import unibl.sni.securevault.dto.SecurityPolicyRequest;
import unibl.sni.securevault.dto.SecurityPolicyResponse;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.service.AuditLogService;
import unibl.sni.securevault.service.SecurityPolicyService;
import unibl.sni.securevault.service.UserService;

@RestController
@RequestMapping("/api/security-policies")
public class SecurityPolicyController {
    private final SecurityPolicyService policyService;
    private final UserService userService;
    private final AuditLogService auditLogService;

    public SecurityPolicyController(SecurityPolicyService policyService,
                                    UserService userService,
                                    AuditLogService auditLogService) {
        this.policyService = policyService;
        this.userService = userService;
        this.auditLogService = auditLogService;
    }

    @GetMapping
    public SecurityPolicyResponse getCurrent() {
        return SecurityPolicyResponse.from(policyService.getCurrent());
    }

    @PutMapping
    public SecurityPolicyResponse update(@AuthenticationPrincipal Jwt jwt,
                                         @Valid @RequestBody SecurityPolicyRequest request) {
        User actor = requireAdmin(jwt);
        var before = policyService.getCurrent();
        var updated = policyService.update(request);

        // Only policy values are audited; never passwords, tokens or key material.
        String metadata = "{\"minMasterPasswordLength\":"
                + updated.getMinMasterPasswordLength()
                + ",\"secretRotationIntervalDays\":"
                + updated.getSecretRotationIntervalDays()
                + ",\"sessionInactivityTimeoutMinutes\":"
                + updated.getSessionDurationMinutes()
                + ",\"maxSessionDurationMinutes\":"
                + updated.getMaxSessionDurationMinutes() + "}";
        auditLogService.record(actor, "SECURITY_POLICY_UPDATE", "SECURITY_POLICY",
                updated.getId().toString(), metadata);

        return SecurityPolicyResponse.from(updated);
    }

    private User requireAdmin(Jwt jwt) {
        String subject = jwt == null ? null : jwt.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new InvalidOperationRequestException("Token subject must not be blank");
        }
        User user = userService.findByKeycloakId(subject)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User is not registered in Secure Vault"));
        if (user.getStatus() != UserStatus.ACTIVE || user.getRole() != Role.ADMIN) {
            throw new InvalidOperationRequestException("Only active administrators can update security policies");
        }
        return user;
    }
}
