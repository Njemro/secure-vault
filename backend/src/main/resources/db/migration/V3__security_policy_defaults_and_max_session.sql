ALTER TABLE security_policies
    ADD COLUMN max_session_duration_minutes INT NOT NULL DEFAULT 600
    AFTER session_duration_minutes;

ALTER TABLE security_policies
    ADD CONSTRAINT chk_security_policies_max_session_minutes
    CHECK (max_session_duration_minutes > 0);

-- Keep the existing column name for compatibility: it represents inactivity timeout.
-- Seed one default row only when the table is empty.
INSERT INTO security_policies (
    id,
    min_master_password_length,
    secret_rotation_interval_days,
    session_duration_minutes,
    max_session_duration_minutes,
    created_at,
    updated_at
)
SELECT
    '00000000-0000-0000-0000-000000000001',
    12,
    90,
    30,
    600,
    CURRENT_TIMESTAMP(6),
    CURRENT_TIMESTAMP(6)
WHERE NOT EXISTS (SELECT 1 FROM security_policies);
