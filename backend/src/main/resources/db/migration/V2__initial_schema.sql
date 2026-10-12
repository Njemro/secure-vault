-- Initial Secure Vault schema.
--
-- Notes:
-- * V1 (comment-only placeholder) was already applied to the Docker MySQL
--   instance, so it must not be modified - the schema ships as V2.
-- * UUIDs are stored as CHAR(36) (readable, portable across MySQL and the H2
--   test database). Timestamps use DATETIME(6) (microsecond precision).
-- * Cryptographic material (encrypted values, wrapped DEKs, IVs, public keys,
--   hashes) uses sized VARBINARY so every byte round-trips without lossy
--   conversion. MySQL reports BLOB columns as Types#LONGVARBINARY while H2
--   reports Types#BLOB, so VARBINARY is used instead: it reports as
--   Types#VARBINARY on both and passes ddl-auto=validate on both.
--   kdf_parameters and metadata use VARCHAR(n) because MySQL TEXT maps to a
--   JDBC type Hibernate would not validate against.
-- * secrets.dek_iv is NOT NULL: secrets are encrypted with AES-256-GCM and
--   the DEK is wrapped with AES-256-GCM under the KEK (AGENTS.md section 4);
--   both operations use a fresh 12-byte IV, stored separately
--   (content_iv vs dek_iv).
-- * Schema constraints and indexes are defined here only; Hibernate runs
--   with ddl-auto=validate and must not create or alter tables.

CREATE TABLE users (
    id          CHAR(36)     NOT NULL,
    keycloak_id VARCHAR(64)  NOT NULL,
    username    VARCHAR(100) NOT NULL,
    role        VARCHAR(10)  NOT NULL,
    status      VARCHAR(12)  NOT NULL,
    created_at  DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uq_users_keycloak_id UNIQUE (keycloak_id),
    CONSTRAINT uq_users_username UNIQUE (username),
    CONSTRAINT chk_users_role CHECK (role IN ('ADMIN', 'TEAM_LEAD', 'DEVELOPER')),
    CONSTRAINT chk_users_status CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DISABLED'))
);

CREATE TABLE user_keys (
    id                    CHAR(36)      NOT NULL,
    user_id               CHAR(36)      NOT NULL,
    public_key            VARBINARY(1024)  NOT NULL,
    encrypted_private_key VARBINARY(4096)  NOT NULL,
    private_key_iv        VARBINARY(128) NOT NULL,
    kdf_algorithm         VARCHAR(50)   NOT NULL,
    kdf_parameters        VARCHAR(2000) NOT NULL,
    created_at            DATETIME(6)   NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uq_user_keys_user_id UNIQUE (user_id)
);
ALTER TABLE user_keys ADD CONSTRAINT fk_user_keys_user_id
    FOREIGN KEY (user_id) REFERENCES users (id);

CREATE TABLE secrets (
    id                  CHAR(36)      NOT NULL,
    owner_id            CHAR(36)      NOT NULL,
    name                VARCHAR(255)  NOT NULL,
    description         VARCHAR(1000) NULL,
    encrypted_value     VARBINARY(50000) NOT NULL,
    encrypted_dek       VARBINARY(1024) NOT NULL,
    content_iv          VARBINARY(128) NOT NULL,
    dek_iv              VARBINARY(128) NOT NULL,
    encryption_algorithm VARCHAR(50)  NOT NULL,
    created_at          DATETIME(6)   NOT NULL,
    last_rotated_at     DATETIME(6)   NULL,
    PRIMARY KEY (id)
);
CREATE INDEX idx_secrets_owner_id ON secrets (owner_id);
ALTER TABLE secrets ADD CONSTRAINT fk_secrets_owner_id
    FOREIGN KEY (owner_id) REFERENCES users (id);

CREATE TABLE secret_shares (
    id              CHAR(36)     NOT NULL,
    secret_id       CHAR(36)     NOT NULL,
    recipient_id    CHAR(36)     NOT NULL,
    encrypted_dek   VARBINARY(1024) NOT NULL,
    created_at      DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uq_secret_shares_secret_recipient UNIQUE (secret_id, recipient_id)
);
CREATE INDEX idx_secret_shares_recipient_id ON secret_shares (recipient_id);
ALTER TABLE secret_shares ADD CONSTRAINT fk_secret_shares_secret_id
    FOREIGN KEY (secret_id) REFERENCES secrets (id);
ALTER TABLE secret_shares ADD CONSTRAINT fk_secret_shares_recipient_id
    FOREIGN KEY (recipient_id) REFERENCES users (id);

CREATE TABLE security_policies (
    id                            CHAR(36)    NOT NULL,
    min_master_password_length    INT         NOT NULL,
    secret_rotation_interval_days INT         NOT NULL,
    session_duration_minutes      INT         NOT NULL,
    created_at                    DATETIME(6) NOT NULL,
    updated_at                    DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT chk_security_policies_min_length CHECK (min_master_password_length >= 8),
    CONSTRAINT chk_security_policies_rotation_days CHECK (secret_rotation_interval_days > 0),
    CONSTRAINT chk_security_policies_session_minutes CHECK (session_duration_minutes > 0)
);

CREATE TABLE audit_logs (
    id            CHAR(36)      NOT NULL,
    event_time    DATETIME(6)   NOT NULL,
    actor_id      CHAR(36)      NULL,
    action        VARCHAR(50)   NOT NULL,
    resource_type VARCHAR(50)   NOT NULL,
    resource_id   VARCHAR(64)   NULL,
    metadata      VARCHAR(2000) NOT NULL,
    previous_hash VARBINARY(32) NOT NULL,
    record_hash   VARBINARY(32) NOT NULL,
    PRIMARY KEY (id)
);
CREATE INDEX idx_audit_logs_event_time ON audit_logs (event_time);
CREATE INDEX idx_audit_logs_actor_id ON audit_logs (actor_id);
CREATE INDEX idx_audit_logs_action ON audit_logs (action);
ALTER TABLE audit_logs ADD CONSTRAINT fk_audit_logs_actor_id
    FOREIGN KEY (actor_id) REFERENCES users (id);

CREATE TABLE honeypot_secrets (
    id            CHAR(36)      NOT NULL,
    owner_id      CHAR(36)      NOT NULL,
    name          VARCHAR(255)  NOT NULL,
    decoy_content VARBINARY(50000) NOT NULL,
    content_iv    VARBINARY(128) NULL,
    metadata      VARCHAR(1000) NOT NULL,
    created_at    DATETIME(6)   NOT NULL,
    PRIMARY KEY (id)
);
CREATE INDEX idx_honeypot_secrets_owner_id ON honeypot_secrets (owner_id);
ALTER TABLE honeypot_secrets ADD CONSTRAINT fk_honeypot_secrets_owner_id
    FOREIGN KEY (owner_id) REFERENCES users (id);

CREATE TABLE security_events (
    id         CHAR(36)      NOT NULL,
    event_time DATETIME(6)   NOT NULL,
    user_id    CHAR(36)      NULL,
    event_type VARCHAR(50)   NOT NULL,
    source_ip  VARCHAR(45)   NULL,
    metadata   VARCHAR(2000) NOT NULL,
    PRIMARY KEY (id)
);
CREATE INDEX idx_security_events_event_time ON security_events (event_time);
CREATE INDEX idx_security_events_event_type ON security_events (event_type);
CREATE INDEX idx_security_events_user_id ON security_events (user_id);
ALTER TABLE security_events ADD CONSTRAINT fk_security_events_user_id
    FOREIGN KEY (user_id) REFERENCES users (id);



