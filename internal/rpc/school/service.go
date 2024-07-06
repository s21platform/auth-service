package school

import (
	"context"
	"fmt"
	"github.com/s21platform/auth-service/internal/config"
	school_proto "github.com/s21platform/school-proto/school-proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"log"
)

type Handle struct {
	client school_proto.SchoolServiceClient
}

func (h *Handle) DoLogin(ctx context.Context, email, password string) (string, error) {
	resp, err := h.client.Login(ctx, &school_proto.SchoolLoginRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		if statusError, ok := status.FromError(err); ok {
			if statusError.Code() == codes.Unavailable {
				return "", status.Error(codes.Unavailable, "School rpc is offline")
			}
			if statusError.Code() == codes.InvalidArgument {
				return "", status.Error(codes.InvalidArgument, "Invalid argument")
			}
		}
		return "", err
	}
	return resp.Token, nil
}

func MustConnect(cfg *config.Config) *Handle {
	Conn, err := grpc.NewClient(fmt.Sprintf("%s:%s", cfg.School.Host, cfg.School.Port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("could not connect to school rpc: %v", err)
	}
	Client := school_proto.NewSchoolServiceClient(Conn)
	return &Handle{client: Client}
}
