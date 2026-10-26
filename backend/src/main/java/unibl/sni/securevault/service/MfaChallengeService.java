package unibl.sni.securevault.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unibl.sni.securevault.entity.MfaChallenge;
import unibl.sni.securevault.exception.InvalidOperationRequestException;
import unibl.sni.securevault.repository.MfaChallengeRepository;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Manages short-lived, single-use MFA challenges issued during login when MFA
 * is required.
 * <p>A challenge is bound to one user, expires after a fixed TTL, and may be
 * attempted only a limited number of times. On successful TOTP verification it
 * is marked as consumed and can never be used again. It is not a JWT and cannot
 * be used to access any protected API endpoint.
 */
@Service
public class MfaChallengeService {

    /** Challenge time-to-live: 5 minutes. */
    private static final long CHALLENGE_TTL_MINUTES = 5;

    /** Maximum number of failed TOTP verification attempts per challenge. */
    private static final int MAX_ATTEMPTS = 5;

    private final MfaChallengeRepository challengeRepository;

    public MfaChallengeService(MfaChallengeRepository challengeRepository) {
        this.challengeRepository = challengeRepository;
    }

    /**
     * Creates a new MFA challenge for the given user. Any existing
     * (unused, unexpired) challenges for the same user are revoked first so
     * that only one challenge is active at a time.
     *
     * @param userId the user the challenge is bound to
     * @return the opaque challenge token to return to the client
     */
    @Transactional
    public UUID createChallenge(UUID userId) {
        // Revoke any existing unused challenges for this user.
        challengeRepository.deleteByUserId(userId);

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiresAt = now.plusMinutes(CHALLENGE_TTL_MINUTES);
        UUID challengeToken = UUID.randomUUID();

        MfaChallenge challenge = new MfaChallenge(userId, challengeToken, expiresAt, MAX_ATTEMPTS);
        challengeRepository.save(challenge);

        return challengeToken;
    }

    /**
     * Validates and consumes a challenge. On success returns the bound user id.
     * The challenge is marked as used so it can never be presented again.
     *
     * @param challengeToken the opaque challenge token from the client
     * @return the user id bound to the challenge
     * @throws InvalidOperationRequestException if the challenge is missing,
     *         expired, already used, or has exceeded its attempt limit
     */
    @Transactional
    public UUID consumeChallenge(UUID challengeToken) {
        if (challengeToken == null) {
            throw new InvalidOperationRequestException("MFA challenge is required");
        }

        MfaChallenge challenge = challengeRepository.findByChallengeToken(challengeToken)
                .orElseThrow(() -> new InvalidOperationRequestException("Invalid or unknown MFA challenge"));

        if (challenge.isUsed()) {
            throw new InvalidOperationRequestException("MFA challenge has already been used");
        }

        if (challenge.isExpired()) {
            throw new InvalidOperationRequestException("MFA challenge has expired");
        }

        if (challenge.attemptsExceeded()) {
            throw new InvalidOperationRequestException("MFA challenge attempt limit exceeded");
        }

        challenge.incrementAttempts();
        challenge.markUsed();
        challengeRepository.save(challenge);

        return challenge.getUserId();
    }

    /**
     * Records a failed verification attempt against the challenge without
     * consuming it. The challenge remains usable until either it succeeds or
     * the attempt limit is reached.
     *
     * @param challengeToken the challenge token
     * @throws InvalidOperationRequestException if the challenge is unknown
     */
    @Transactional
    public void recordFailedAttempt(UUID challengeToken) {
        MfaChallenge challenge = challengeRepository.findByChallengeToken(challengeToken)
                .orElseThrow(() -> new InvalidOperationRequestException("Invalid or unknown MFA challenge"));

        challenge.incrementAttempts();
        challengeRepository.save(challenge);
    }

    /**
     * Removes all expired challenges. Safe to call periodically.
     */
    @Transactional
    public void purgeExpired() {
        challengeRepository.deleteExpired(LocalDateTime.now());
    }
}