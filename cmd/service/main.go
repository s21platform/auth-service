package main

import (
	"fmt"
	"github.com/s21platform/auth-service/internal/client/notification"
	"log"
	"net"

	"google.golang.org/grpc"

	logger_lib "github.com/s21platform/logger-lib"
	"github.com/s21platform/metrics-lib/pkg"

	"github.com/s21platform/auth-service/internal/client/community"
	"github.com/s21platform/auth-service/internal/client/school"
	"github.com/s21platform/auth-service/internal/client/user"
	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/internal/infra"
	"github.com/s21platform/auth-service/internal/service"
	"github.com/s21platform/auth-service/pkg/auth"
)

func main() {
	cfg := config.MustLoad()
	logger := logger_lib.New(cfg.Logger.Host, cfg.Logger.Port, cfg.Service.Name, cfg.Platform.Env)

	metrics, err := pkg.NewMetrics(cfg.Metrics.Host, cfg.Metrics.Port, cfg.Service.Name, cfg.Platform.Env)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create metrics object: %v", err))
		log.Fatal("failed to create metrics object: ", err)
	}
	defer metrics.Disconnect()

	schoolClient := school.MustConnect(cfg)
	communityClient := community.MustConnect(cfg)
	userClient := user.MustConnect(cfg)
	notificationClient := notification.New(cfg)

	authService := service.New(schoolClient, communityClient, userClient, cfg.Service.Secret, notificationClient)
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			infra.MetricsInterceptor(metrics),
			infra.Logger(logger),
		),
	)

	auth.RegisterAuthServiceServer(grpcServer, authService)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.Service.Port))
	if err != nil {
		logger.Error(fmt.Sprintf("failed to start TCP listener: %v", err))
	}

	if err = grpcServer.Serve(listener); err != nil {
		logger.Error(fmt.Sprintf("failed to start gRPC listener: %v", err))
	}
}
