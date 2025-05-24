package model

type Session struct {
	UserUUID         string `db:"user_uuid"`
	RefreshTokenHash string `db:"refresh_token_hash"`
	UserAgent        string `db:"user_agent"`
	IP               string `db:"ip_address"`
}
