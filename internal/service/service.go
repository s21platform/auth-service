package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auth_proto "github.com/s21platform/auth-proto/auth-proto"
	logger_lib "github.com/s21platform/logger-lib"

	"github.com/s21platform/auth-service/internal/config"
)

type Service struct {
	auth_proto.UnimplementedAuthServiceServer
	communityS CommunityS
	schoolS    SchoolS
	userS      UserS
	secret     string
}

func New(schoolService SchoolS, communityService CommunityS, userS UserS, secret string) *Service {
	return &Service{
		schoolS:    schoolService,
		communityS: communityService,
		userS:      userS,
		secret:     secret,
	}
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
	return &auth_proto.LoginResponse{Jwt: tokenString}, nil
}
