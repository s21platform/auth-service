package school

import (
	"fmt"
	"github.com/s21platform/auth-service/internal/config"
	"google.golang.org/grpc"
	"log"
)

type SchoolService struct {
	Conn *grpc.ClientConn
}

func NewSchoolService(cfg *config.Config) *SchoolService {
	conn, err := grpc.Dial(fmt.Sprintf("%s:%s", cfg.School.Host, cfg.School.Port), grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Cannot dial to school service: %s", err)
	}
	return &SchoolService{Conn: conn}
}
