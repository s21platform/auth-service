-- +goose Up
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE TABLE IF NOT EXISTS platform_accounts
(
    user_uuid           UUID PRIMARY KEY             DEFAULT gen_random_uuid(),
    nickname            VARCHAR(64) UNIQUE,
    email               VARCHAR(255) UNIQUE NOT NULL,
    password_hash       VARCHAR(255)        NOT NULL,
    password_salt       VARCHAR(255)        NOT NULL,
    hash_algorithm      VARCHAR(50)         NOT NULL DEFAULT 'bcrypt',
    failed_attempts     INT                          DEFAULT 0,
    locked_until        TIMESTAMP,
    password_changed_at TIMESTAMP,
    created_at          TIMESTAMP           NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP
);

-- +goose Down
DROP TABLE IF EXISTS platform_accounts;
DROP EXTENSION IF EXISTS pgcrypto;
