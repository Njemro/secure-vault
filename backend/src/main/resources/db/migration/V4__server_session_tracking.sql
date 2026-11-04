CREATE TABLE app_sessions (
    session_id VARCHAR(128) NOT NULL,
    user_subject VARCHAR(128) NOT NULL,
    started_at DATETIME(6) NOT NULL,
    last_activity_at DATETIME(6) NOT NULL,

    PRIMARY KEY (session_id),
    INDEX idx_app_sessions_user_subject (user_subject),
    INDEX idx_app_sessions_last_activity (last_activity_at)
);