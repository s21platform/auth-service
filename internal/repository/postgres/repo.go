package postgres

import (
	"context"
	"fmt"
	sq "github.com/Masterminds/squirrel"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/s21platform/auth-service/internal/config"
	"log"
)

type Repo struct {
	conn *sqlx.DB
}

func New(cfg *config.Config) *Repo {
	conStr := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		cfg.Postgres.User, cfg.Postgres.Password, cfg.Postgres.Database, cfg.Postgres.Host, cfg.Postgres.Port)

	conn, err := sqlx.Connect("postgres", conStr)
	if err != nil {
		log.Fatal("error connect: ", err)
	}

	if err := conn.Ping(); err != nil {
		log.Fatal("error ping: ", err)
	}
	return &Repo{
		conn: conn,
	}
}

func (r *Repo) PendingRegistration(ctx context.Context, email string, code string) (string, error) {
	query, args, err := sq.
		Insert(`pending_registrations`).
		Columns(`email`, `verification_code`).
		Values(email, code).
		Suffix("RETURNING uuid").
		PlaceholderFormat(sq.Dollar).
		ToSql()

	if err != nil {
		return "", fmt.Errorf("failed to build sql query: %v", err)
	}

	var uuid string
	err = r.conn.QueryRowContext(ctx, query, args...).Scan(&uuid)
	if err != nil {
		return "", fmt.Errorf("failed to execute sql query: %v", err)
	}

	return uuid, nil
}
