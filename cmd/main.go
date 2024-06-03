package main

import (
	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/internal/server"
)

func main() {
	cfg := config.MustLoad()
	service := server.NewServer(cfg)
	service.Run()
}
