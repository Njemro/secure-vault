package unibl.sni.securevault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import unibl.sni.securevault.entity.MfaCredential;

import java.util.Optional;
import java.util.UUID;

public interface MfaCredentialRepository extends JpaRepository<MfaCredential, UUID> {

    Optional<MfaCredential> findByUserId(UUID userId);
}
