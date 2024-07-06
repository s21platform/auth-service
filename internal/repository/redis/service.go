package redis

import "github.com/s21platform/auth-service/internal/config"

type Repository struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Repository {
	return &Repository{cfg: cfg}
}

func (r *Repository) Get() {}

func (r *Repository) Set() {}
