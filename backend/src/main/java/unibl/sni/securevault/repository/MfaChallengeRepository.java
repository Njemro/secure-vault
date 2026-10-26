package unibl.sni.securevault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import unibl.sni.securevault.entity.MfaChallenge;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for MFA challenge records. Challenges are short-lived, single-use
 * tokens issued during login when MFA is required.
 */
public interface MfaChallengeRepository extends JpaRepository<MfaChallenge, UUID> {

    Optional<MfaChallenge> findByChallengeToken(UUID challengeToken);

    List<MfaChallenge> findByUserId(UUID userId);

    @Query("DELETE FROM MfaChallenge m WHERE m.userId = :userId")
    void deleteByUserId(@Param("userId") UUID userId);

    @Query("DELETE FROM MfaChallenge m WHERE m.expiresAt < :now")
    int deleteExpired(@Param("now") java.time.LocalDateTime now);
}