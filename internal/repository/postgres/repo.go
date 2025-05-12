package postgres

import (
	"context"
	"fmt"
	"log"

	sq "github.com/Masterminds/squirrel"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // Импорт драйвера PostgreSQL

	"github.com/s21platform/auth-service/internal/config"
)

type Key string

const KeyTx = Key("tx_repo")

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
