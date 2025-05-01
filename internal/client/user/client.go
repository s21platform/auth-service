package user

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	userproto "github.com/s21platform/user-proto/user-proto"

	"github.com/s21platform/auth-service/internal/config"
)

type Client struct {
	client userproto.UserServiceClient
}

func MustConnect(cfg *config.Config) *Client {
	conn, err := grpc.NewClient(fmt.Sprintf("%s:%s", cfg.Community.Host, cfg.Community.Port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to connect to user service: %v", err)
	}
	client := userproto.NewUserServiceClient(conn)
	return &Client{client: client}
}

func (c *Client) GetOrSetUser(ctx context.Context, email string) (string, error) {
	resp, err := c.client.GetUserByLogin(ctx, &userproto.GetUserByLoginIn{
		Login: email,
	})
	if err != nil {
		return "", status.Error(codes.Internal, err.Error())
	}
	return resp.Uuid, nil
}
