
package unibl.sni.securevault.controller;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import unibl.sni.securevault.dto.AdminUserResponse;
import unibl.sni.securevault.dto.DeveloperResponse;
import unibl.sni.securevault.dto.PublicKeyResponse;
import unibl.sni.securevault.dto.UpdateUserRoleRequest;
import unibl.sni.securevault.dto.UpdateUserStatusRequest;
import unibl.sni.securevault.dto.UserKeyRegisterRequest;
import unibl.sni.securevault.dto.UserKeyResponse;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.service.AuditLogService;
import unibl.sni.securevault.service.UserKeyService;
import unibl.sni.securevault.service.UserService;
import unibl.sni.securevault.service.KeycloakAdminService;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final UserKeyService userKeyService;
    private final AuditLogService auditLogService;
    private final KeycloakAdminService keycloakAdminService;

    public UserController(
            UserService userService,
            UserKeyService userKeyService,
            AuditLogService auditLogService,
            KeycloakAdminService keycloakAdminService) {
        this.userService = userService;
        this.userKeyService = userKeyService;
        this.auditLogService = auditLogService;
        this.keycloakAdminService = keycloakAdminService;
    }

    @GetMapping("/{id}/public-key")
    public ResponseEntity<PublicKeyResponse> getPublicKey(
            @PathVariable UUID id) {
        User user = userService.getById(id);

        var key = userKeyService.findByUserId(id)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User has no key record: " + id));

        return ResponseEntity.ok(new PublicKeyResponse(
                user.getId(),
                user.getUsername(),
                key.getPublicKey()));
    }

    @PutMapping("/keys")
    public ResponseEntity<Void> registerKeys(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody UserKeyRegisterRequest request) {

        User current = requireCurrentUser(jwt);

        userKeyService.registerOrUpdateKeys(
                current,
                request.publicKey(),
                request.encryptedPrivateKey(),
                request.privateKeyIv(),
                request.kdfAlgorithm(),
                request.kdfParameters());

        auditLogService.record(
                current,
                "USER_KEY_REGISTER",
                "USER_KEY",
                current.getId().toString(),
                "{}");

        return ResponseEntity.ok().build();
    }

    @GetMapping("/me/keys")
    public ResponseEntity<UserKeyResponse> getMyKeys(
            @AuthenticationPrincipal Jwt jwt) {

        User current = requireCurrentUser(jwt);

        var key = userKeyService.findByUserId(current.getId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User has no key record: " + current.getId()));

        return ResponseEntity.ok(new UserKeyResponse(
                current.getId(),
                key.getPublicKey(),
                key.getEncryptedPrivateKey(),
                key.getPrivateKeyIv(),
                key.getKdfAlgorithm(),
                key.getKdfParameters(),
                key.getCreatedAt()));
    }

    @GetMapping("/developers")
    public ResponseEntity<List<DeveloperResponse>> getDevelopers(
            @AuthenticationPrincipal Jwt jwt) {

        User current = requireCurrentUser(jwt);

        if (current.getRole() != Role.TEAM_LEAD
                || current.getStatus() != unibl.sni.securevault.entity.UserStatus.ACTIVE) {
            throw new AccessDeniedException(
                    "Only active Team Leads can view developers.");
        }

        List<DeveloperResponse> developers = userService
                .getActiveDevelopers()
                .stream()
                .filter(developer ->
                        userKeyService.findByUserId(developer.getId()).isPresent())
                .map(developer -> new DeveloperResponse(
                        developer.getId(),
                        developer.getUsername()))
                .toList();

        return ResponseEntity.ok(developers);
    }

    // ADMIN: pregled svih korisničkih naloga
    @GetMapping
    public ResponseEntity<List<AdminUserResponse>> getAllUsers(
            @AuthenticationPrincipal Jwt jwt) {

        User current = requireAdmin(jwt);

        List<AdminUserResponse> users = userService.getAllUsers()
                .stream()
                .map(AdminUserResponse::from)
                .toList();

        return ResponseEntity.ok(users);
    }

    // ADMIN: detalji korisničkog naloga
    @GetMapping("/{id}")
    public ResponseEntity<AdminUserResponse> getUserDetails(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID id) {
        requireAdmin(jwt);
        return ResponseEntity.ok(AdminUserResponse.from(userService.getById(id)));
    }

    // ADMIN: promjena korisničke uloge
    @PutMapping("/{id}/role")
    public ResponseEntity<AdminUserResponse> updateUserRole(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID id,
            @Valid @RequestBody UpdateUserRoleRequest request) {

        User current = requireAdmin(jwt);

        User target = userService.getById(id);
        if (target.getId().equals(current.getId()) && request.role() != Role.ADMIN) {
            throw new AccessDeniedException("Admin cannot remove their own ADMIN role.");
        }

        Role previousKeycloakRole = keycloakAdminService.replaceApplicationRole(
                target.getKeycloakId(), request.role());
        User updated;
        try {
            // Opoziv svih sesija mora uspjeti prije nego promjenu potvrdimo lokalno.
            keycloakAdminService.logoutUser(target.getKeycloakId());
            updated = userService.changeUserRole(id, request.role(), current);
        } catch (RuntimeException error) {
            try {
                keycloakAdminService.replaceApplicationRole(
                        target.getKeycloakId(), previousKeycloakRole);
            } catch (RuntimeException rollbackError) {
                error.addSuppressed(rollbackError);
            }
            throw error;
        }

        auditLogService.record(current, "USER_ROLE_UPDATE", "USER", id.toString(),
        "{\"previousRole\":\"" + previousKeycloakRole.name() + "\",\"newRole\":\"" + request.role().name() + "\"}");

        return ResponseEntity.ok(AdminUserResponse.from(updated));
    }

    // ADMIN: promjena statusa korisničkog naloga
    @PutMapping("/{id}/status")
    public ResponseEntity<AdminUserResponse> updateUserStatus(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID id,
            @Valid @RequestBody UpdateUserStatusRequest request) {

        User current = requireAdmin(jwt);

        User target = userService.getById(id);
        if (target.getId().equals(current.getId())
                && request.status() != unibl.sni.securevault.entity.UserStatus.ACTIVE) {
            throw new AccessDeniedException("Admin cannot suspend or disable their own account.");
        }
        if (target.getStatus() == request.status()) {
            return ResponseEntity.ok(AdminUserResponse.from(target));
        }
        boolean enabled = request.status() == unibl.sni.securevault.entity.UserStatus.ACTIVE;
        keycloakAdminService.setUserEnabled(target.getKeycloakId(), enabled);
        User updated;
        try {
            keycloakAdminService.logoutUser(target.getKeycloakId());
            updated = userService.changeUserStatus(id, request.status(), current);
        } catch (RuntimeException error) {
            try {
                keycloakAdminService.setUserEnabled(target.getKeycloakId(),
                        target.getStatus() == unibl.sni.securevault.entity.UserStatus.ACTIVE);
            } catch (RuntimeException rollbackError) {
                error.addSuppressed(rollbackError);
            }
            throw error;
        }

        auditLogService.record(
                current,
                "USER_STATUS_UPDATE",
                "USER",
                id.toString(),
                "{\"status\":\"" + request.status().name() + "\"}");

        return ResponseEntity.ok(AdminUserResponse.from(updated));
    }

    private User requireAdmin(Jwt jwt) {
        User current = requireCurrentUser(jwt);

        if (current.getRole() != Role.ADMIN
                || current.getStatus() != unibl.sni.securevault.entity.UserStatus.ACTIVE) {
            throw new AccessDeniedException(
                    "Only active Admin users can manage accounts.");
        }

        return current;
    }

    private User requireCurrentUser(Jwt jwt) {
        String keycloakId = jwt != null ? jwt.getSubject() : null;

        if (keycloakId == null || keycloakId.isBlank()) {
            throw new ResourceNotFoundException(
                    "Token subject (sub) claim must not be blank");
        }

        return userService.findByKeycloakId(keycloakId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User is not registered in Secure Vault for this token subject"));
    }
}
