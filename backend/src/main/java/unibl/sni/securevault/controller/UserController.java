package unibl.sni.securevault.controller;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import unibl.sni.securevault.dto.PublicKeyResponse;
import unibl.sni.securevault.dto.UserKeyRegisterRequest;
import unibl.sni.securevault.dto.UserKeyResponse;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.service.AuditLogService;
import unibl.sni.securevault.service.UserKeyService;
import unibl.sni.securevault.service.UserService;

import java.util.UUID;

/**
 * Read-only user-related endpoints used by the sharing flow. The backend never
 * sees plaintext private keys; the public-key endpoint only exposes the public
 * key so a sharing client can wrap a DEK for the recipient (RSA-OAEP,
 * AGENTS.md section 5).
 * <p>Key registration lets the authenticated user upload their client-encrypted
 * key material (public key + encrypted private key). The acting user is always
 * resolved from the JWT {@code sub} claim; a client-supplied user id is never
 * trusted to determine whose keys are stored.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final UserKeyService userKeyService;
    private final AuditLogService auditLogService;

    public UserController(UserService userService, UserKeyService userKeyService,
                          AuditLogService auditLogService) {
        this.userService = userService;
        this.userKeyService = userKeyService;
        this.auditLogService = auditLogService;
    }

    /**
     * Returns the user's public key and username so a sharing client can wrap
     * a DEK for them. The encrypted private key is never included in this or
     * any other ordinary response (AGENTS.md section 6).
     */
    @GetMapping("/{id}/public-key")
    public ResponseEntity<PublicKeyResponse> getPublicKey(@PathVariable UUID id) {
        User user = userService.getById(id);
        var key = userKeyService.findByUserId(id)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User has no key record: " + id));
        return ResponseEntity.ok(new PublicKeyResponse(
                user.getId(), user.getUsername(), key.getPublicKey()));
    }

    /**
     * Registers or replaces the authenticated user's key material. The acting
     * user is resolved exclusively from the JWT {@code sub} claim; no
     * client-supplied user id is accepted. All cryptographic values are opaque
     * client-produced bytes - the backend never sees the master password or a
     * decrypted private key.
     */
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
        auditLogService.record(current, "USER_KEY_REGISTER", "USER_KEY",
                current.getId().toString(), "{}");
        return ResponseEntity.ok().build();
    }

    /**
     * Returns the authenticated user's complete key material, including the
     * client-side encrypted private key. Only the owner may retrieve their own
     * keys; there is no endpoint that exposes another user's encrypted private
     * key.
     */
    @GetMapping("/me/keys")
    public ResponseEntity<UserKeyResponse> getMyKeys(@AuthenticationPrincipal Jwt jwt) {
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

    /**
     * Maps the JWT subject (Keycloak {@code sub}) to the local user record.
     * A syntactically valid token for an unknown subject means the account is
     * not provisioned in Secure Vault; such callers get a 404 for the user
     * resource rather than any vault data.
     */
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