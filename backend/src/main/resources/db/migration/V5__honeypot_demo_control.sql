CREATE TABLE honeypot_demo_state (
    id TINYINT NOT NULL,
    enabled_until DATETIME(6) NULL,
    enabled_by CHAR(36) NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),

    CONSTRAINT chk_honeypot_demo_singleton
        CHECK (id = 1),

    CONSTRAINT fk_honeypot_demo_enabled_by
        FOREIGN KEY (enabled_by) REFERENCES users (id)
);

INSERT INTO honeypot_demo_state (
    id,
    enabled_until,
    enabled_by,
    updated_at
)
VALUES (
    1,
    NULL,
    NULL,
    CURRENT_TIMESTAMP(6)
);