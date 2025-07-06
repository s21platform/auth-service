package model

import "time"

type Session struct {
	ID                   string    `db:"id"`
	UserUUID             string    `db:"user_uuid"`
	RefreshTokenHash     string    `db:"refresh_token_hash"`
	UserAgent            string    `db:"user_agent"`
	IP                   string    `db:"ip_address"`
	IsActive             bool      `db:"is_active"`
	IsBlocked            bool      `db:"is_blocked"`
	RefreshTokenIssuedAt time.Time `db:"refresh_token_issued_at"`
	CreatedAt            time.Time `db:"created_at"`
	UpdatedAt            time.Time `db:"updated_at"`
	ExpiresAt            time.Time `db:"expires_at"`
}
