package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.MfaCredential;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.repository.MfaCredentialRepository;
import unibl.sni.securevault.repository.UserRepository;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Service
public class MfaService {

    private final TotpService totpService;
    private final MfaCredentialRepository mfaCredentialRepository;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;
    private final AesGcmEncryptionService encryptionService;

    public MfaService(TotpService totpService,
                      MfaCredentialRepository mfaCredentialRepository,
                      UserRepository userRepository,
                      AuditLogService auditLogService,
                      AesGcmEncryptionService encryptionService) {
        this.totpService = totpService;
        this.mfaCredentialRepository = mfaCredentialRepository;
        this.userRepository = userRepository;
        this.auditLogService = auditLogService;
        this.encryptionService = encryptionService;
    }

    @Transactional
    public MfaEnrollmentResult beginEnrollment(UUID userId, String username) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));
        if (mfaCredentialRepository.findByUserId(userId).isPresent()) {
            throw new InvalidOperationRequestException("MFA is already enrolled for this user");
        }
        String secret = totpService.generateSecret();
        String provisioningUri = totpService.provisioningUri(username, secret);
        AesGcmEncryptionService.EncryptedSecret encrypted =
                encryptionService.encrypt(secret.getBytes(StandardCharsets.UTF_8));
        MfaCredential credential = new MfaCredential(user, encrypted.ciphertext(), encrypted.iv());
        mfaCredentialRepository.save(credential);
        auditLogService.record(user, "MFA_ENROLLMENT_STARTED", "MFA_CREDENTIAL",
                credential.getId().toString(), "{\"userId\":\"" + userId + "\"}");
        return new MfaEnrollmentResult(provisioningUri, secret);
    }

    @Transactional
    public void confirmEnrollment(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));
        MfaCredential credential = mfaCredentialRepository.findByUserId(userId)
                .orElseThrow(() -> new InvalidOperationRequestException("MFA enrollment not started"));
        String secret = decryptSecret(credential);
        if (!totpService.verifyCode(secret, code)) {
            auditLogService.record(user, "MFA_ENROLLMENT_FAILED", "MFA_CREDENTIAL",
                    credential.getId().toString(), "{\"userId\":\"" + userId + "\"}");
            throw new InvalidOperationRequestException("Invalid verification code");
        }
        user.setMfaEnabled(true);
        userRepository.save(user);
        auditLogService.record(user, "MFA_ENROLLMENT_COMPLETED", "MFA_CREDENTIAL",
                credential.getId().toString(), "{\"userId\":\"" + userId + "\"}");
    }

    @Transactional
    public void disableMfa(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));
        if (!user.isMfaEnabled()) {
            throw new InvalidOperationRequestException("MFA is not enabled for this user");
        }
        MfaCredential credential = mfaCredentialRepository.findByUserId(userId)
                .orElseThrow(() -> new InvalidOperationRequestException("No MFA credential found"));
        String secret = decryptSecret(credential);
        if (!totpService.verifyCode(secret, code)) {
            auditLogService.record(user, "MFA_DISABLE_FAILED", "MFA_CREDENTIAL",
                    credential.getId().toString(), "{\"userId\":\"" + userId + "\"}");
            throw new InvalidOperationRequestException("Invalid verification code");
        }
        user.setMfaEnabled(false);
        mfaCredentialRepository.delete(credential);
        userRepository.save(user);
        auditLogService.record(user, "MFA_DISABLED", "MFA_CREDENTIAL",
                credential.getId().toString(), "{\"userId\":\"" + userId + "\"}");
    }

    public boolean isMfaEnabled(UUID userId) {
        return userRepository.findById(userId)
                .map(User::isMfaEnabled)
                .orElse(false);
    }

    public boolean verifyLoginCode(UUID userId, String code) {
        MfaCredential credential = mfaCredentialRepository.findByUserId(userId)
                .orElseThrow(() -> new InvalidOperationRequestException("MFA not enrolled"));
        String secret = decryptSecret(credential);
        return totpService.verifyCode(secret, code);
    }

    private String decryptSecret(MfaCredential credential) {
        byte[] plaintext = encryptionService.decrypt(credential.getEncryptedSecret(), credential.getSecretIv());
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public record MfaEnrollmentResult(String provisioningUri, String secret) {
    }
}