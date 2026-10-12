package unibl.sni.securevault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import unibl.sni.securevault.entity.SecretShare;

import java.util.List;
import java.util.UUID;

public interface SecretShareRepository extends JpaRepository<SecretShare, UUID> {

    List<SecretShare> findByRecipientId(UUID recipientId);

    List<SecretShare> findBySecretId(UUID secretId);
}
