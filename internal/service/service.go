package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	logger_lib "github.com/s21platform/logger-lib"

	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/pkg/auth"
)

type Service struct {
	auth.UnimplementedAuthServiceServer
	repository DBRepo
	schoolS    SchoolS
	communityS CommunityS
	userS      UserS
	secret     string
}

func New(repository DBRepo, schoolService SchoolS, communityService CommunityS, userS UserS, secret string) *Service {
	return &Service{
		repository: repository,
		schoolS:    schoolService,
		communityS: communityService,
		userS:      userS,
		secret:     secret,
	}
}

func (s *Service) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	logger := logger_lib.FromContext(ctx, config.KeyLogger)
	logger.AddFuncName("Login")

	req.Username = strings.ToLower(req.Username)
	username := req.Username
	if !strings.HasSuffix(req.Username, "@student.21-school.ru") {
		username += "@student.21-school.ru"
	} else {
		req.Username = strings.ReplaceAll(req.Username, "@student.21-school.ru", "")
	}

	isPeer, err := s.communityS.CheckPeer(ctx, username)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to check user from community-service: %v", err))
		return nil, err
	}

	if !isPeer {
		logger.Error(fmt.Sprintf("user is not a community member: %v", err))
		return nil, status.Errorf(codes.FailedPrecondition, "Вы не являетесь участником s21")
	}

	t, err := s.schoolS.DoLogin(ctx, req.Username, req.Password)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to auth user in school-service: %v", err))
		return nil, status.Errorf(codes.Unauthenticated, "Неверный логин или пароль")
	}

	resp, err := s.userS.GetOrSetUser(ctx, username)
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
	tokenString, err := token.SignedString([]byte(s.secret))
	if err != nil {
		logger.Error(fmt.Sprintf("failed to sign token: %v", err))
		return nil, err
	}
	return &auth.LoginResponse{Jwt: tokenString}, nil
}

func (s *Service) CheckEmailAvailability(ctx context.Context, in *auth.CheckEmailAvailabilityIn) (*auth.CheckEmailAvailabilityOut, error) {
	logger := logger_lib.FromContext(ctx, config.KeyLogger)
	logger.AddFuncName("CheckEmailAvailability")

	// todo добавить rate limiter

	if in.Email == "" {
		logger.Error("email is required")
		return nil, fmt.Errorf("email is required")
	}

	in.Email = strings.ToLower(in.Email)
	isAvailable, err := s.repository.IsEmailAvailable(ctx, in.Email)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to check email: %v", err))
		return nil, err
	}

	return &auth.CheckEmailAvailabilityOut{IsAvailable: isAvailable}, nil
}
