package user

import (
	"context"
	"fmt"
	"github.com/s21platform/auth-service/internal/config"
	userproto "github.com/s21platform/user-proto/user-proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
)

type Service struct {
	client userproto.UserServiceClient
}

func NewService(cfg *config.Config) *Service {
	connStr := fmt.Sprintf("%s:%s", cfg.User.Host, cfg.User.Port)
	conn, err := grpc.NewClient(connStr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	client := userproto.NewUserServiceClient(conn)
	return &Service{client}
}

func (s *Service) GetOrSetUser(ctx context.Context, email string) (string, error) {
	resp, err := s.client.GetUserByLogin(ctx, &userproto.GetUserByLoginIn{
		Login: email,
	})
	if err != nil {
		return "", status.Error(codes.Internal, err.Error())
	}
	return resp.Uuid, nil
}
