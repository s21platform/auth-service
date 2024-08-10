package main

import (
	"fmt"
	auth_proto "github.com/s21platform/auth-proto/auth-proto"
	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/internal/repository/redis"
	"github.com/s21platform/auth-service/internal/rpc/community"
	"github.com/s21platform/auth-service/internal/rpc/school"
	"github.com/s21platform/auth-service/internal/service"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {
	// Чтение конфига
	cfg := config.MustLoad()

	// Создание объектов для работы сервера
	redisRepo := redis.New(cfg)
	schoolService := school.MustConnect(cfg)
	communityService := community.MustConnect(cfg)

	// Создание объекта самого сервера
	thisService := service.New(cfg, schoolService, communityService, redisRepo)

	// Создание gRPC сервера и регистрация обработчика
	s := grpc.NewServer()
	auth_proto.RegisterAuthServiceServer(s, thisService)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.Service.Port))
	if err != nil {
		log.Fatalf("Cannnot listen port: %s; Error: %s", cfg.Service.Port, err)
	}
	log.Println("starting grpc server")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Cannnot start service: %s; Error: %s", cfg.Service.Port, err)
	}
}
