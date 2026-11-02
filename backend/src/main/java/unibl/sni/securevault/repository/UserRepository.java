package unibl.sni.securevault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserStatus;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByKeycloakId(String keycloakId);

    Optional<User> findByUsername(String username);

    List<User> findByRoleAndStatus(Role role, UserStatus status);
}