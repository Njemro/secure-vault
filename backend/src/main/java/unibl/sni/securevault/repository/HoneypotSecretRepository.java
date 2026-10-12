package unibl.sni.securevault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import unibl.sni.securevault.entity.HoneypotSecret;

import java.util.UUID;

public interface HoneypotSecretRepository extends JpaRepository<HoneypotSecret, UUID> {
}
