package main

import (
	"fmt"
	"log"
	"net"

	auth_proto "github.com/s21platform/auth-proto/auth-proto"
	"github.com/s21platform/auth-service/internal/client/community"
	"github.com/s21platform/auth-service/internal/client/school"
	"github.com/s21platform/auth-service/internal/client/user"
	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/internal/infra"
	"github.com/s21platform/auth-service/internal/repository/redis"
	"github.com/s21platform/auth-service/internal/service"
	logger_lib "github.com/s21platform/logger-lib"
	"github.com/s21platform/metrics-lib/pkg"
	"google.golang.org/grpc"
)

func main() {
	// Чтение конфига
	cfg := config.MustLoad()

	metrics, err := pkg.NewMetrics(cfg.Metrics.Host, cfg.Metrics.Port, cfg.Service.Name, cfg.Platform.Env)
	if err != nil {
		log.Fatalf("cannot init metrics, err: %v", err)
	}

	logger := logger_lib.New(cfg.Logger.Host, cfg.Logger.Port, cfg.Service.Name, cfg.Platform.Env)

	// Создание объектов для работы сервера
	redisRepo := redis.New(cfg)
	schoolClient := school.MustConnect(cfg)
	communityClient := community.MustConnect(cfg)
	userClient := user.MustConnect(cfg)

	// Создание объекта самого сервера
	thisService := service.New(cfg, schoolClient, communityClient, redisRepo, userClient)

	// Создание gRPC сервера и регистрация обработчика
	s := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			infra.MetricsInterceptor(metrics),
			infra.Logger(logger),
		),
	)
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
