package user

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/s21platform/user-service/pkg/user"

	"github.com/s21platform/auth-service/internal/config"
)

type Client struct {
	client user.UserServiceClient
}

func MustConnect(cfg *config.Config) *Client {
	conn, err := grpc.NewClient(fmt.Sprintf("%s:%s", cfg.User.Host, cfg.User.Port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to connect to user service: %v", err)
	}
	client := user.NewUserServiceClient(conn)
	return &Client{client: client}
}

func (c *Client) GetOrSetUser(ctx context.Context, email string) (string, error) {
	resp, err := c.client.GetUserByLogin(ctx, &user.GetUserByLoginIn{
		Login: email,
	})
	if err != nil {
		return "", status.Error(codes.Internal, err.Error())
	}
	return resp.Uuid, nil
}

func (c *Client) CreateUser(ctx context.Context, email string) (*user.CreateUserOut, error) {
	resp, err := c.client.CreateUser(ctx, &user.CreateUserIn{Email: email})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return resp, nil
}
