package unibl.sni.securevault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import unibl.sni.securevault.entity.SecretShare;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SecretShareRepository extends JpaRepository<SecretShare, UUID> {

    List<SecretShare> findByRecipientId(UUID recipientId);

    List<SecretShare> findBySecretId(UUID secretId);

    /**
     * Finds all shares for a recipient, eagerly fetching the secret and its
     * owner so the controller can read ownerId and secret fields after the
     * transaction ends ({@code spring.jpa.open-in-view=false}).
     */
    @Query("""
        SELECT s FROM SecretShare s
        LEFT JOIN FETCH s.secret
        LEFT JOIN FETCH s.secret.owner
        WHERE s.recipient.id = :recipientId""")
    List<SecretShare> findByRecipientIdWithSecretAndOwner(@Param("recipientId") UUID recipientId);

    /**
     * Finds the share for a given secret/recipient pair, eagerly fetching the
     * secret and its owner.
     */
    @Query("""
        SELECT s FROM SecretShare s
        LEFT JOIN FETCH s.secret
        LEFT JOIN FETCH s.secret.owner
        WHERE s.secret.id = :secretId AND s.recipient.id = :recipientId""")
    Optional<SecretShare> findBySecretIdAndRecipientId(
            @Param("secretId") UUID secretId, @Param("recipientId") UUID recipientId);
}
