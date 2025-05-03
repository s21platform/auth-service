-- +goose Up
CREATE TABLE IF NOT EXISTS sessions
(
    id                 UUID PRIMARY KEY             DEFAULT gen_random_uuid(),
    user_uuid          UUID                NOT NULL,
    refresh_token_hash VARCHAR(255) UNIQUE NOT NULL,
    user_agent         TEXT,
    ip_address         VARCHAR(45),
    is_active          BOOLEAN             NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMP           NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMP,
    expires_at         TIMESTAMP           NOT NULL,
    FOREIGN KEY (user_uuid) REFERENCES platform_accounts (user_uuid)
);

-- +goose Down
DROP TABLE IF EXISTS sessions;
