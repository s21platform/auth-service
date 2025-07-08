package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // Импорт драйвера PostgreSQL

	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/internal/model"
)

type Repository struct {
	*sqlx.DB
}

func New(cfg *config.Config) *Repository {
	conStr := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		cfg.Postgres.User, cfg.Postgres.Password, cfg.Postgres.Database, cfg.Postgres.Host, cfg.Postgres.Port)

	conn, err := sqlx.Connect("postgres", conStr)
	if err != nil {
		log.Fatal("failed to connect: ", err)
	}

	return &Repository{
		conn,
	}
}

func (r *Repository) Close() {
	_ = r.DB.Close()
}

func (r *Repository) IsEmailAvailable(ctx context.Context, email string) (bool, error) {
	query, args, err := sq.
		Select("COUNT(*)").
		From("platform_accounts").
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return false, fmt.Errorf("failed to build query: %v", err)
	}

	var count int
	err = r.Chk(ctx).GetContext(ctx, &count, query, args...)
	if err != nil {
		return false, fmt.Errorf("failed to check email availability: %v", err)
	}

	return count == 0, nil
}

func (r *Repository) InsertPendingRegistration(ctx context.Context, email, code string) (string, error) {
	query, args, err := sq.
		Insert("pending_registrations").
		Columns("email", "verification_code").
		Values(email, code).
		Suffix("RETURNING uuid").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return "", fmt.Errorf("failed to build sql query: %v", err)
	}

	var uuid string
	err = r.Chk(ctx).GetContext(ctx, &uuid, query, args...)
	if err != nil {
		return "", fmt.Errorf("failed to execute sql query: %v", err)
	}

	return uuid, nil
}

func (r *Repository) GetVerificationCode(ctx context.Context, codeLookupUUID string) (string, error) {
	query, args, err := sq.
		Select("verification_code").
		From("pending_registrations").
		Where(sq.Eq{"uuid": codeLookupUUID}).
		Where(sq.Expr("expires_at > NOW()")).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return "", fmt.Errorf("failed to build sql query: %w", err)
	}

	var code string
	err = r.Chk(ctx).GetContext(ctx, &code, query, args...)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("no valid verification code found for uuid: %s", codeLookupUUID)
		}
		return "", fmt.Errorf("failed to execute sql query: %w", err)
	}

	return code, nil
}

func (r *Repository) SaveNewUser(ctx context.Context, account *model.PlatformAccount) error {
	query, args, err := sq.
		Insert("platform_accounts").
		Columns("user_uuid", "nickname", "email", "password_hash", "password_salt", "hash_algorithm").
		Values(account.UserUUID, account.Nickname, account.Email, account.PasswordHash, account.PasswordSalt, account.HashAlgorithm).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql query: %w", err)
	}

	_, err = r.Chk(ctx).ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to execute sql query: %w", err)
	}

	return nil
}

func (r *Repository) CreateSession(ctx context.Context, session *model.Session) (string, error) {
	query, args, err := sq.
		Insert("sessions").
		Columns("user_uuid", "refresh_token_hash", "user_agent", "ip_address", "expires_at").
		Values(
			session.UserUUID,
			session.RefreshTokenHash,
			session.UserAgent,
			session.IP,
			time.Now().Add(30*24*time.Hour),
		).
		Suffix("RETURNING id").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return "", fmt.Errorf("failed to build sql query: %w", err)
	}

	var sessionID string
	err = r.Chk(ctx).GetContext(ctx, &sessionID, query, args...)
	if err != nil {
		return "", fmt.Errorf("failed to execute sql query: %w", err)
	}

	return sessionID, nil
}

func (r *Repository) GetUserByNickname(ctx context.Context, nickname string) (*model.PlatformAccount, error) {
	query, args, err := sq.
		Select("user_uuid", "nickname", "email", "password_hash", "password_salt", "hash_algorithm").
		From("platform_accounts").
		Where(sq.Eq{"nickname": nickname}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql query: %w", err)
	}

	var account model.PlatformAccount
	err = r.Chk(ctx).GetContext(ctx, &account, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute sql query: %w", err)
	}

	return &account, nil
}

func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*model.PlatformAccount, error) {
	query, args, err := sq.
		Select("user_uuid", "nickname", "email", "password_hash", "password_salt", "hash_algorithm").
		From("platform_accounts").
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql query: %w", err)
	}

	var account model.PlatformAccount
	err = r.Chk(ctx).GetContext(ctx, &account, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute sql query: %w", err)
	}

	return &account, nil
}

func (r *Repository) GetUserByUUID(ctx context.Context, uuid string) (*model.PlatformAccount, error) {
	query, args, err := sq.
		Select("user_uuid", "nickname", "email", "password_hash", "password_salt", "hash_algorithm").
		From("platform_accounts").
		Where(sq.Eq{"user_uuid": uuid}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql query: %w", err)
	}

	var account model.PlatformAccount
	err = r.Chk(ctx).GetContext(ctx, &account, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute sql query: %w", err)
	}

	return &account, nil
}

func (r *Repository) GetSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (*model.Session, error) {
	query, args, err := sq.Select("id", "user_uuid", "refresh_token_hash", "user_agent", "ip_address", "is_active", "is_blocked", "refresh_token_issued_at", "created_at", "updated_at", "expires_at").
		From("sessions").
		Where(sq.And{
			sq.Eq{"refresh_token_hash": refreshTokenHash},
			sq.GtOrEq{"expires_at": time.Now()},
			sq.Eq{"is_blocked": false},
		}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql query: %w", err)
	}

	var session model.Session
	err = r.Chk(ctx).GetContext(ctx, &session, query, args...)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no valid session found for refresh token")
		}
		return nil, fmt.Errorf("failed to execute sql query: %w", err)
	}

	return &session, nil
}
