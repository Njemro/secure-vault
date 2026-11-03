package unibl.sni.securevault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import unibl.sni.securevault.entity.SecurityPolicy;

import java.util.Optional;
import java.util.UUID;

public interface SecurityPolicyRepository extends JpaRepository<SecurityPolicy, UUID> {
    Optional<SecurityPolicy> findFirstByOrderByCreatedAtAsc();
}
