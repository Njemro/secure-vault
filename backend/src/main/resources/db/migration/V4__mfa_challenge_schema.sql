-- MFA challenge schema.
--
-- Stores short-lived, single-use MFA challenges issued during login when MFA
-- is required. Challenges are not JWTs and cannot be used to access protected
-- endpoints; they are only looked up to authorize TOTP verification.
CREATE TABLE mfa_challenges (
    id            CHAR(36)     NOT NULL,
    user_id       CHAR(36)     NOT NULL,
    challenge_token CHAR(36)  NOT NULL UNIQUE,
    expires_at    DATETIME(6)  NOT NULL,
    used_at       DATETIME(6)  NULL,
    attempt_count INT          NOT NULL DEFAULT 0,
    max_attempts  INT          NOT NULL DEFAULT 5,
    created_at    DATETIME(6)  NOT NULL,
    PRIMARY KEY (id)
);
CREATE INDEX idx_mfa_challenges_user_id ON mfa_challenges (user_id);
CREATE INDEX idx_mfa_challenges_expires_at ON mfa_challenges (expires_at);