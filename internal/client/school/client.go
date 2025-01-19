package school

import (
	"context"
	"fmt"
	"log"

	"github.com/s21platform/auth-service/internal/config"
	school_proto "github.com/s21platform/school-proto/school-proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	client school_proto.SchoolServiceClient
}

func (c *Client) DoLogin(ctx context.Context, email, password string) (string, error) {
	resp, err := c.client.Login(ctx, &school_proto.SchoolLoginRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		return "", err
	}
	return resp.Token, nil
}

func MustConnect(cfg *config.Config) *Client {
	Conn, err := grpc.NewClient(fmt.Sprintf("%s:%s", cfg.School.Host, cfg.School.Port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("could not connect to school client: %v", err)
	}
	client := school_proto.NewSchoolServiceClient(Conn)
	return &Client{client: client}
}
