//go:generate mockgen -destination=mock_contract_test.go -package=${GOPACKAGE} -source=contract.go
package service

import "context"

type SchoolS interface {
	DoLogin(ctx context.Context, email, password string) (string, error)
}

type CommunityS interface {
	CheckPeer(ctx context.Context, email string) (bool, error)
}

type UserS interface {
	GetOrSetUser(ctx context.Context, email string) (string, error)
}

type NotificationC interface {
	SendVerificationCode(ctx context.Context, email string, code string) error
}

type DbRepo interface {
	PendingRegistration(ctx context.Context, email string, code string) (string, error)
}
