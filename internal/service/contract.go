//go:generate mockgen -destination=mock_contract_test.go -package=${GOPACKAGE} -source=contract.go
package service

import (
	"context"
)

type DBRepo interface {
	IsEmailAvailable(ctx context.Context, email string) (bool, error)
	InsertPendingRegistration(ctx context.Context, email, code string) (string, error)
	GetVerificationCode(ctx context.Context, codeLookupUUID string) (string, error)
}

type SchoolS interface {
	DoLogin(ctx context.Context, email, password string) (string, error)
}

type CommunityS interface {
	CheckPeer(ctx context.Context, email string) (bool, error)
}

type UserS interface {
	GetOrSetUser(ctx context.Context, email string) (string, error)
}

type NotificationS interface {
	SendVerificationCode(ctx context.Context, email, code string) error
}
