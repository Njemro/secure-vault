package unibl.sni.securevault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import unibl.sni.securevault.entity.HoneypotSecret;

import java.util.UUID;
import java.util.List;

public interface HoneypotSecretRepository extends JpaRepository<HoneypotSecret, UUID> {

    List<HoneypotSecret> findAllByOwnerId(UUID ownerId);

    boolean existsByOwnerId(UUID ownerId);
}
