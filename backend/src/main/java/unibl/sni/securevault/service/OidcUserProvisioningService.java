package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.oauth2.jwt.Jwt;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.repository.UserRepository;

import java.util.Optional;

/**
 * Provisions a local Secure Vault profile for a verified Keycloak OIDC identity.
 * The Keycloak subject is the stable identity key. New brokered identities get
 * the least-privileged DEVELOPER role and their own hidden honeytoken.
 */
@Service
public class OidcUserProvisioningService {

    private final UserRepository userRepository;
    private final HoneypotSecretService honeypotSecretService;

    public OidcUserProvisioningService(
            UserRepository userRepository,
            HoneypotSecretService honeypotSecretService) {
        this.userRepository = userRepository;
        this.honeypotSecretService = honeypotSecretService;
    }

    @Transactional
    public User findOrProvision(Jwt jwt) {
        if (jwt == null || jwt.getSubject() == null || jwt.getSubject().isBlank()) {
            throw new IllegalArgumentException("A verified OIDC subject is required.");
        }

        Optional<User> existing = userRepository.findByKeycloakId(jwt.getSubject());
        if (existing.isPresent()) {
            return existing.get();
        }

        String username = resolveUsername(jwt);
        User newUser = new User(
                jwt.getSubject(),
                username,
                Role.DEVELOPER,
                UserStatus.ACTIVE);

        User saved = userRepository.save(newUser);
        honeypotSecretService.ensureHoneypotExists(saved);
        return saved;
    }

    private String resolveUsername(Jwt jwt) {
        String username = firstNonBlank(
                jwt.getClaimAsString("preferred_username"),
                jwt.getClaimAsString("email"));

        if (username == null) {
            username = "oidc-" + jwt.getSubject().substring(0, Math.min(12, jwt.getSubject().length()));
        }

        username = username.trim();
        if (username.length() > 100) {
            username = username.substring(0, 100);
        }

        if (userRepository.findByUsername(username).isPresent()) {
            String compactSubject = jwt.getSubject().replace("-", "");
            String suffix = "-" + compactSubject.substring(0, Math.min(8, compactSubject.length()));
            int baseLength = Math.max(1, 100 - suffix.length());
            username = username.substring(0, Math.min(username.length(), baseLength)) + suffix;
        }

        if (userRepository.findByUsername(username).isPresent()) {
            username = "oidc-" + jwt.getSubject();
        }

        return username.length() > 100 ? username.substring(0, 100) : username;
    }

    private static String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank()) return first;
        if (second != null && !second.isBlank()) return second;
        return null;
    }
}
