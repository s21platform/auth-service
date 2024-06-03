package school

import (
	"fmt"
	"github.com/s21platform/auth-service/internal/config"
	school_proto "github.com/s21platform/school-proto/school-proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
)

type Service struct {
	Conn   *grpc.ClientConn
	Client school_proto.SchoolServiceClient
}

func MustConnect(cfg *config.Config) *Service {
	Conn, err := grpc.NewClient(fmt.Sprintf("%s:%s", cfg.School.Host, cfg.School.Port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("could not connect to school service: %v", err)
	}
	Client := school_proto.NewSchoolServiceClient(Conn)
	return &Service{Conn: Conn, Client: Client}
}
