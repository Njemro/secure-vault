package unibl.sni.securevault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import unibl.sni.securevault.entity.Secret;

import java.util.List;
import java.util.UUID;

public interface SecretRepository extends JpaRepository<Secret, UUID> {

    List<Secret> findByOwnerId(UUID ownerId);
}
