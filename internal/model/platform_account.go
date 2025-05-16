package model

type PlatformAccount struct {
	UserUUID      string `db:"user_uuid"`
	Nickname      string `db:"nickname"`
	Email         string `db:"email"`
	PasswordHash  string `db:"password_hash"`
	PasswordSalt  string `db:"password_salt"`
	HashAlgorithm string `db:"hash_algorithm"`
}
