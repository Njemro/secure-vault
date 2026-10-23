-- MFA (TOTP) schema additions.
-- * Adds mfa_enabled column to users (defaults to false).
-- * Creates mfa_credentials table for encrypted TOTP secrets.
ALTER TABLE users
    ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE
    AFTER status;

CREATE TABLE mfa_credentials (
    id            CHAR(36)      NOT NULL,
    user_id       CHAR(36)      NOT NULL,
    encrypted_secret VARBINARY(4096) NOT NULL,
    secret_iv     VARBINARY(128) NOT NULL,
    created_at    DATETIME(6)   NOT NULL,
    updated_at    DATETIME(6)   NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uq_mfa_credentials_user_id UNIQUE (user_id)
);
ALTER TABLE mfa_credentials ADD CONSTRAINT fk_mfa_credentials_user_id
    FOREIGN KEY (user_id) REFERENCES users (id);
