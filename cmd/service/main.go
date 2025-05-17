package main

import (
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	kafkalib "github.com/s21platform/kafka-lib"
	logger_lib "github.com/s21platform/logger-lib"
	"github.com/s21platform/metrics-lib/pkg"

	"github.com/s21platform/auth-service/internal/client/community"
	"github.com/s21platform/auth-service/internal/client/notification"
	"github.com/s21platform/auth-service/internal/client/school"
	"github.com/s21platform/auth-service/internal/client/user"
	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/internal/infra"
	"github.com/s21platform/auth-service/internal/pkg/tx"
	"github.com/s21platform/auth-service/internal/repository/postgres"
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

	dbRepo := postgres.New(cfg)
	defer dbRepo.Close()

	schoolClient := school.MustConnect(cfg)
	communityClient := community.MustConnect(cfg)
	userClient := user.MustConnect(cfg)
	notificationClient := notification.New(cfg)

	producerConfig := kafkalib.DefaultProducerConfig(cfg.Kafka.Host, cfg.Kafka.Port, cfg.Kafka.Topic)
	kafkaProducer := kafkalib.NewProducer(producerConfig)

	authService := service.New(dbRepo, schoolClient, communityClient, userClient, notificationClient, kafkaProducer, cfg.Service)
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			infra.MetricsInterceptor(metrics),
			infra.Logger(logger),
			tx.TxMiddleWire(dbRepo),
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
