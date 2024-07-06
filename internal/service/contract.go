package service

import "context"

type SchoolS interface {
	DoLogin(ctx context.Context, email, password string) (string, error)
}

type RedisR interface {
	Get()
	Set()
}
