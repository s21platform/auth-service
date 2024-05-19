package main

import (
	"fmt"
	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/internal/usecase/grpc"
	"log"
)

func main() {
	cfg := config.MustLoad()
	server := grpc.MustAuthService(cfg)
	fmt.Println("Starting service on port", cfg.Service.Port)
	if err := server.Server.Serve(server.Lis); err != nil {
		log.Fatalf("Error while starting service: %s", err)
	}
}
