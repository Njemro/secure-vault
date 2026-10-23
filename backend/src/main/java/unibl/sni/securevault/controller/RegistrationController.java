package unibl.sni.securevault.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import unibl.sni.securevault.dto.RegisterRequest;
import unibl.sni.securevault.dto.RegisterResponse;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.repository.UserRepository;
import unibl.sni.securevault.service.KeycloakAdminService;

import java.util.UUID;

/**
 * Registration endpoint for new Secure Vault accounts.
 * <p>Creates the user in Keycloak (authentication identity) and provisions the
 * corresponding local MySQL user record. The vault master password is never
 * part of this request - it is established client-side during key setup
 * (AGENTS.md section 8). Keycloak login password and master password remain
 * logically separate.
 * <p>If Keycloak user creation succeeds but local provisioning fails, the
 * Keycloak user is deleted (best-effort rollback) so no orphaned account is
 * left behind.
 */
@RestController
@RequestMapping("/api/auth")
public class RegistrationController {

    private final KeycloakAdminService keycloakAdminService;
    private final UserRepository userRepository;

    public RegistrationController(KeycloakAdminService keycloakAdminService,
                                  UserRepository userRepository) {
        this.keycloakAdminService = keycloakAdminService;
        this.userRepository = userRepository;
    }

    /**
     * Registers a new user: creates the Keycloak account and provisions the
     * local user record. Returns the Keycloak user id and username on success.
     * <p>Unauthenticated access is permitted (see SecurityConfig).
     */
    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        if (userRepository.findByUsername(request.username()).isPresent()) {
            throw new InvalidOperationRequestException("Username is already taken");
        }

        String keycloakId;
        try {
            keycloakId = keycloakAdminService.createUser(
                    request.username(), request.email(), request.keycloakPassword());
        } catch (Exception e) {
            throw new InvalidOperationRequestException("Failed to create Keycloak account: " + e.getMessage());
        }

        try {
            User user = new User(keycloakId, request.username(), Role.DEVELOPER, UserStatus.ACTIVE);
            userRepository.save(user);
        } catch (Exception e) {
            // Local provisioning failed after Keycloak creation: roll back the
            // Keycloak user so no orphaned account remains.
            keycloakAdminService.deleteUser(keycloakId);
            throw new InvalidOperationRequestException("Failed to provision local account: " + e.getMessage());
        }

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new RegisterResponse(keycloakId, request.username(),
                        "Registration complete. Log in to Keycloak, then set up your encryption keys."));
    }
}