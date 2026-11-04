
package unibl.sni.securevault.service;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserStatus;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.exception.ResourceNotFoundException;
import unibl.sni.securevault.repository.UserRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public Optional<User> findByKeycloakId(String keycloakId) {
        if (keycloakId == null || keycloakId.isBlank()) {
            throw new InvalidOperationRequestException(
                    "keycloakId must not be blank");
        }

        return userRepository.findByKeycloakId(keycloakId);
    }

    @Transactional(readOnly = true)
    public Optional<UserStatus> findStatusByKeycloakId(String keycloakId) {
        return userRepository.findByKeycloakId(keycloakId).map(User::getStatus);
    }

    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new InvalidOperationRequestException(
                    "username must not be blank");
        }

        return userRepository.findByUsername(username);
    }

    @Transactional(readOnly = true)
    public User getById(UUID userId) {
        if (userId == null) {
            throw new InvalidOperationRequestException(
                    "userId must not be null");
        }

        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User not found: " + userId));
    }

    @Transactional(readOnly = true)
    public List<User> getActiveDevelopers() {
        return userRepository.findByRoleAndStatus(
                Role.DEVELOPER,
                UserStatus.ACTIVE
        );
    }

    // ADMIN: pregled svih korisničkih naloga
    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    // ADMIN: promjena korisničke uloge
    @Transactional
    public User changeUserRole(UUID userId, Role newRole, User currentAdmin) {
        validateAdmin(currentAdmin);

        if (userId == null || newRole == null) {
            throw new InvalidOperationRequestException(
                    "User ID and role must not be null.");
        }

        User target = getById(userId);

        if (target.getId().equals(currentAdmin.getId())
                && newRole != Role.ADMIN) {
            throw new AccessDeniedException(
                    "Admin cannot remove their own ADMIN role.");
        }

        target.changeRole(newRole);

        return userRepository.save(target);
    }

    // ADMIN: promjena statusa korisničkog naloga
    @Transactional
    public User changeUserStatus(
            UUID userId,
            UserStatus newStatus,
            User currentAdmin) {

        validateAdmin(currentAdmin);

        if (userId == null || newStatus == null) {
            throw new InvalidOperationRequestException(
                    "User ID and status must not be null.");
        }

        User target = getById(userId);

        if (target.getId().equals(currentAdmin.getId())
                && newStatus != UserStatus.ACTIVE) {
            throw new AccessDeniedException(
                    "Admin cannot suspend or disable their own account.");
        }

        target.changeStatus(newStatus);

        return userRepository.save(target);
    }

    private void validateAdmin(User currentAdmin) {
        if (currentAdmin == null
                || currentAdmin.getRole() != Role.ADMIN
                || currentAdmin.getStatus() != UserStatus.ACTIVE) {
            throw new AccessDeniedException(
                    "Only active Admin users can manage accounts.");
        }
    }
}
