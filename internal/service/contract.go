//go:generate mockgen -destination=mock_contract_test.go -package=${GOPACKAGE} -source=contract.go
package service

import (
	"context"

	"github.com/s21platform/user-service/pkg/user"

	"github.com/s21platform/auth-service/internal/model"
)

type DBRepo interface {
	IsEmailAvailable(ctx context.Context, email string) (bool, error)
	InsertPendingRegistration(ctx context.Context, email, code string) (string, error)
	GetVerificationCode(ctx context.Context, codeLookupUUID string) (string, error)
	SaveNewUser(ctx context.Context, account *model.PlatformAccount) error
	CreateSession(ctx context.Context, session *model.Session) (string, error)
	GetUserByNickname(ctx context.Context, nickname string) (*model.PlatformAccount, error)
	GetUserByEmail(ctx context.Context, email string) (*model.PlatformAccount, error)
	GetUserByUUID(ctx context.Context, uuid string) (*model.PlatformAccount, error)
	GetSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (*model.Session, error)
}

type SchoolS interface {
	DoLogin(ctx context.Context, email, password string) (string, error)
}

type CommunityS interface {
	CheckPeer(ctx context.Context, email string) (bool, error)
}

type UserS interface {
	GetOrSetUser(ctx context.Context, email string) (string, error)
	CreateUser(ctx context.Context, email string) (*user.CreateUserOut, error)
}

type NotificationS interface {
	SendVerificationCode(ctx context.Context, email, code string) error
}

type KafkaProducer interface {
	ProduceMessage(ctx context.Context, message interface{}, key interface{}) error
}
