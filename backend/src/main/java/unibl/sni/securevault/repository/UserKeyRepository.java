package unibl.sni.securevault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import unibl.sni.securevault.entity.UserKey;

import java.util.Optional;
import java.util.UUID;

public interface UserKeyRepository extends JpaRepository<UserKey, UUID> {

    Optional<UserKey> findByUserId(UUID userId);
}
