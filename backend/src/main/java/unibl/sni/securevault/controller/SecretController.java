package unibl.sni.securevault.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import unibl.sni.securevault.dto.RecipientShareInput;
import unibl.sni.securevault.dto.SecretCreateRequest;
import unibl.sni.securevault.dto.SecretResponse;
import unibl.sni.securevault.dto.SecretShareCreateRequest;
import unibl.sni.securevault.dto.SecretShareResponse;
import unibl.sni.securevault.dto.SecretUpdateRequest;
import unibl.sni.securevault.dto.SharedSecretResponse;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.Secret;
import unibl.sni.securevault.entity.SecretShare;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.service.AuditLogService;
import unibl.sni.securevault.service.SecretService;
import unibl.sni.securevault.service.SecretShareService;
import unibl.sni.securevault.service.UserService;

import java.util.List;
import java.util.UUID;

/**
 * Owner-scoped CRUD for encrypted secrets.
 *
 * <p>The acting user is resolved exclusively from the authenticated
 * Keycloak JWT (the {@code sub} claim, matched against {@code users.keycloak_id});
 * it is never taken from the request payload. Every operation is scoped to
 * that user, so a caller can only list, read, update or delete their own
 * secrets (AGENTS.md sections 1 and 8).
 *
 * <p>Requests carry client-produced ciphertext only. The controller never
 * generates, unwraps, decrypts or re-encrypts any cryptographic value, and it
 * never sees the master password (zero-knowledge architecture).
 *
 * <p>Every successful operation is appended to the SHA-256 audit hash chain
 * via {@link AuditLogService}; the chain itself (canonical form, previous
 * link, hashing) is generated inside that service, never here. Audit metadata
 * carries only safe values - never ciphertext, secret names or key material
 * (AGENTS.md section 12).
 */
@RestController
@RequestMapping("/api/secrets")
public class SecretController {

    private final SecretService secretService;
    private final UserService userService;
    private final SecretShareService secretShareService;
    private final AuditLogService auditLogService;

    public SecretController(SecretService secretService, UserService userService,
                            SecretShareService secretShareService, AuditLogService auditLogService) {
        this.secretService = secretService;
        this.userService = userService;
        this.secretShareService = secretShareService;
        this.auditLogService = auditLogService;
    }

    @PostMapping
    public ResponseEntity<SecretResponse> createSecret(@AuthenticationPrincipal Jwt jwt,
                                                       @Valid @RequestBody SecretCreateRequest request) {
        User owner = requireCurrentUser(jwt);
        Secret secret = secretService.createSecret(owner.getId(), request.name(), request.description(),
                request.encryptedValue(), request.encryptedDek(), request.contentIv(), request.dekIv(),
                request.encryptionAlgorithm());
        auditLogService.record(owner, "SECRET_CREATE", "SECRET", secret.getId().toString(), "{}");
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(secret, owner.getId()));
    }

    @GetMapping
    public List<SecretResponse> listOwnSecrets(@AuthenticationPrincipal Jwt jwt) {
        User current = requireCurrentUser(jwt);
        List<SecretResponse> secrets = secretService.findByOwnerId(current.getId()).stream()
                .map(secret -> toResponse(secret, current.getId()))
                .toList();
        auditLogService.record(current, "SECRET_LIST", "SECRET", null,
                "{\"count\":" + secrets.size() + "}");
        return secrets;
    }

    @GetMapping("/{id}")
    public SecretResponse getSecret(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        User current = requireCurrentUser(jwt);
        SecretResponse response = toResponse(secretService.getOwnedSecret(id, current.getId()), current.getId());
        auditLogService.record(current, "SECRET_READ", "SECRET", id.toString(), "{}");
        return response;
    }

    @PutMapping("/{id}")
    public SecretResponse updateSecret(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id,
                                       @Valid @RequestBody SecretUpdateRequest request) {
        User current = requireCurrentUser(jwt);
        Secret updated = secretService.updateOwnedSecret(id, current.getId(), request.name(),
                request.description(), request.encryptedValue(), request.encryptedDek(),
                request.contentIv(), request.dekIv(), request.encryptionAlgorithm());
        auditLogService.record(current, "SECRET_UPDATE", "SECRET", id.toString(), "{}");
        return toResponse(updated, current.getId());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteSecret(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        User current = requireCurrentUser(jwt);
        secretService.deleteOwnedSecret(id, current.getId());
        auditLogService.record(current, "SECRET_DELETE", "SECRET", id.toString(), "{}");
        return ResponseEntity.noContent().build();
    }

    // ------------------------------------------------------------------
    // Secret sharing (Team Lead owner shares with Developer recipients)
    // ------------------------------------------------------------------

    /**
     * Shares a secret with one or more Developer recipients. Only the secret
     * owner with role TEAM_LEAD may share. Each recipient's DEK is already
     * wrapped client-side (RSA-OAEP with the recipient's public key); the
     * backend performs no cryptography and never sees an unwrapped DEK.
     * The secret's encrypted content, IV and owner-wrapped DEK are unchanged.
     */
    @PostMapping("/{id}/shares")
    public ResponseEntity<List<SecretShareResponse>> shareSecret(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID id,
            @Valid @RequestBody SecretShareCreateRequest request) {
        User actor = requireCurrentUser(jwt);
        if (actor.getRole() != Role.TEAM_LEAD) {
            throw new InvalidOperationRequestException("Only team leads can share secrets");
        }

        List<UUID> recipientIds = request.recipients().stream()
                .map(RecipientShareInput::recipientId).toList();
        List<byte[]> encryptedDeks = request.recipients().stream()
                .map(RecipientShareInput::encryptedDek).toList();

        // Recipients must be Developers.
        for (UUID recipientId : recipientIds) {
            User recipient = userService.getById(recipientId);
            if (recipient.getRole() != Role.DEVELOPER) {
                throw new InvalidOperationRequestException(
                        "Recipient must be a Developer: " + recipientId);
            }
        }

        List<SecretShare> shares = secretShareService.createShares(
                id, actor.getId(), recipientIds, encryptedDeks);

        auditLogService.record(actor, "SECRET_SHARE", "SECRET", id.toString(),
                "{\"recipientCount\":" + shares.size() + "}");

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(shares.stream().map(SecretController::toShareResponse).toList());
    }

    /**
     * Lists secrets shared with the authenticated user as recipient. Returns
     * ciphertext, IVs and the recipient-specific wrapped DEK for each shared
     * secret. The original secret ciphertext, IV and owner-wrapped DEK are
     * never modified by sharing.
     */
    @GetMapping("/shared")
    public List<SharedSecretResponse> listSharedWithMe(@AuthenticationPrincipal Jwt jwt) {
        User current = requireCurrentUser(jwt);
        List<SecretShare> shares = secretShareService.findByRecipientIdWithSecretAndOwner(
                current.getId());
        List<SharedSecretResponse> responses = shares.stream()
                .map(share -> toSharedSecretResponse(share, share.getEncryptedDek()))
                .toList();
        auditLogService.record(current, "SHARED_SECRET_LIST", "SECRET", null,
                "{\"count\":" + responses.size() + "}");
        return responses;
    }

    /**
     * Returns one shared secret: its ciphertext, IVs and the DEK wrapped for
     * the authenticated recipient. Only the recipient of the share may read it.
     */
    @GetMapping("/shared/{id}")
    public SharedSecretResponse getSharedSecret(
            @AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        User current = requireCurrentUser(jwt);
        SecretShare share = secretShareService.findShareBySecretAndRecipient(id, current.getId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Shared secret not found: " + id));
        auditLogService.record(current, "SHARED_SECRET_READ", "SECRET", id.toString(), "{}");
        return toSharedSecretResponse(share, share.getEncryptedDek());
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
            throw new InvalidOperationRequestException("Token subject (sub) claim must not be blank");
        }
        return userService.findByKeycloakId(keycloakId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User is not registered in Secure Vault for this token subject"));
    }

    /**
     * The owner id is passed in explicitly (the acting user is already
     * resolved) so no lazy relation is dereferenced outside a transaction
     * ({@code spring.jpa.open-in-view=false}).
     */
    private static SecretResponse toResponse(Secret secret, UUID ownerId) {
        return new SecretResponse(secret.getId(), ownerId, secret.getName(), secret.getDescription(),
                secret.getEncryptedValue(), secret.getEncryptedDek(), secret.getContentIv(),
                secret.getDekIv(), secret.getEncryptionAlgorithm(), secret.getCreatedAt(),
                secret.getLastRotatedAt());
    }

    private static SecretShareResponse toShareResponse(SecretShare share) {
        return new SecretShareResponse(share.getId(), share.getSecret().getId(),
                share.getRecipient().getId(), share.getEncryptedDek(), share.getCreatedAt());
    }

    private static SharedSecretResponse toSharedSecretResponse(SecretShare share,
                                                               byte[] recipientEncryptedDek) {
        Secret secret = share.getSecret();
        return new SharedSecretResponse(secret.getId(), secret.getOwner().getId(),
                secret.getName(), secret.getDescription(), secret.getEncryptedValue(),
                secret.getContentIv(), secret.getEncryptionAlgorithm(), secret.getCreatedAt(),
                share.getId(), recipientEncryptedDek);
    }
}