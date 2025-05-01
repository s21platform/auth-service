package community

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	community_proto "github.com/s21platform/community-proto/community-proto"

	"github.com/s21platform/auth-service/internal/config"
)

type Client struct {
	client community_proto.CommunityServiceClient
}

func MustConnect(cfg *config.Config) *Client {
	conn, err := grpc.NewClient(fmt.Sprintf("%s:%s", cfg.Community.Host, cfg.Community.Port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to connect to community service: %v", err)
	}
	client := community_proto.NewCommunityServiceClient(conn)
	return &Client{client: client}
}

func (c *Client) CheckPeer(ctx context.Context, email string) (bool, error) {
	resp, err := c.client.IsPeerExist(ctx, &community_proto.EmailIn{Email: email})
	if err != nil {
		return false, err
	}
	return resp.IsExist, nil
}
