-- +goose Up
CREATE TABLE IF NOT EXISTS platform_accounts
(
    user_uuid           UUID PRIMARY KEY,
    nickname            VARCHAR(64) UNIQUE,
    password_hash       VARCHAR(255) NOT NULL,
    password_salt       VARCHAR(255) NOT NULL,
    hash_algorithm      VARCHAR(50)  NOT NULL DEFAULT 'bcrypt',
    failed_attempts     INT                   DEFAULT 0,
    locked_until        TIMESTAMP,
    password_changed_at TIMESTAMP,
    created_at          TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP
);

-- +goose Down
DROP TABLE IF EXISTS platform_accounts;
