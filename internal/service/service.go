package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	logger_lib "github.com/s21platform/logger-lib"

	"github.com/dgrijalva/jwt-go"
	auth_proto "github.com/s21platform/auth-proto/auth-proto"
	"github.com/s21platform/auth-service/internal/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	auth_proto.UnimplementedAuthServiceServer
	cfg        *config.Config
	communityS CommunityS
	schoolS    SchoolS
	redisR     RedisR
	uS         UserService
}

func (s *Service) Login(ctx context.Context, req *auth_proto.LoginRequest) (*auth_proto.LoginResponse, error) {
	logger := logger_lib.FromContext(ctx, config.KeyLogger)
	logger.AddFuncName("Login")

	req.Username = strings.ToLower(req.Username)
	username := req.Username
	if !strings.HasSuffix(req.Username, "@student.21-school.ru") {
		username += "@student.21-school.ru"
	} else {
		req.Username = strings.ReplaceAll(req.Username, "@student.21-school.ru", "")
	}

	is, err := s.communityS.CheckPeer(ctx, username)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to check user from community-service: %v", err))
		log.Println("Error checking user", err)
		return nil, err
	}

	if !is {
		logger.Error(fmt.Sprintf("user is not a community member: %v", err))
		log.Println("User isn't a community")
		return nil, status.Errorf(codes.FailedPrecondition, "Вы не являетесь участником s21")
	}

	t, err := s.schoolS.DoLogin(ctx, req.Username, req.Password)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to auth user in school-service: %v", err))
		log.Println("Error do login", err)
		return nil, status.Errorf(codes.Unauthenticated, "Неверный логин или пароль")
	}

	resp, err := s.uS.GetOrSetUser(ctx, username)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to get (or set) user into user-servcie: %v", err))
		return nil, status.Errorf(codes.Internal, "Не удалось получить данные пользователя")
	}

	data := jwt.MapClaims{
		"username":    username,
		"role":        "student",
		"accessToken": t,
		"exp":         time.Now().Add(time.Hour * 9).Unix(),
		"uid":         resp,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, data)
	tokenString, err := token.SignedString([]byte(s.cfg.Service.Secret))
	if err != nil {
		logger.Error(fmt.Sprintf("failed to generate token: %v", err))
		log.Println("Error signing token", err)
		return nil, err
	}
	return &auth_proto.LoginResponse{Jwt: tokenString}, nil
}

func New(cfg *config.Config, schoolService SchoolS, communityService CommunityS, redis RedisR, uS UserService) *Service {
	return &Service{
		cfg:        cfg,
		schoolS:    schoolService,
		communityS: communityService,
		redisR:     redis,
		uS:         uS,
	}
}
