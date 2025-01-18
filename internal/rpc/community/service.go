package community

import (
	"context"
	"fmt"
	"log"

	"github.com/s21platform/auth-service/internal/config"
	community_proto "github.com/s21platform/community-proto/community-proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Handle struct {
	client community_proto.CommunityServiceClient
}

func (h *Handle) CheckPeer(ctx context.Context, email string) (bool, error) {
	resp, err := h.client.IsPeerExist(ctx, &community_proto.EmailIn{Email: email})
	if err != nil {
		return false, err
	}
	return resp.IsExist, nil
}

func MustConnect(cfg *config.Config) *Handle {
	conn, err := grpc.NewClient(fmt.Sprintf("%s:%s", cfg.Community.Host, cfg.Community.Port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Could not connect to community service: %v", err)
	}
	Client := community_proto.NewCommunityServiceClient(conn)
	return &Handle{client: Client}
}
