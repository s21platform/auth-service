-- +goose Up
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE TABLE IF NOT EXISTS pending_registrations
(
    uuid              UUID PRIMARY KEY      DEFAULT gen_random_uuid(),
    email             VARCHAR(255) NOT NULL,
    verification_code VARCHAR(6)   NOT NULL,
    expires_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP + INTERVAL '5 minutes',
    created_at        TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- +goose Down
DROP TABLE IF EXISTS pending_registrations;
DROP EXTENSION IF EXISTS pgcrypto;
