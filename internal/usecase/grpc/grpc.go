package grpc

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	auth_proto "github.com/s21platform/auth-proto/auth-proto"
	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/internal/repository/school"
	school_proto "github.com/s21platform/school-proto/school-proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"log"
	"net"
	"strings"
	"time"
)

type AuthService struct {
	auth_proto.UnimplementedAuthServiceServer
	cfg    *config.Config
	Lis    net.Listener
	Server *grpc.Server
}

func (s *AuthService) Login(ctx context.Context, request *auth_proto.LoginRequest) (*auth_proto.LoginResponse, error) {
	fmt.Println("Login request")
	username := request.Username
	if !strings.HasSuffix(request.Username, "@student.21-school.ru") {
		username += "@student.21-school.ru"
	}
	schoolService := school.NewSchoolService(s.cfg)
	defer schoolService.Conn.Close()
	client := school_proto.NewSchoolServiceClient(schoolService.Conn)
	response, err := client.Login(ctx, &school_proto.SchoolLoginRequest{Email: username, Password: request.Password})
	if err != nil {
		if statusError, ok := status.FromError(err); ok {
			if statusError.Code() == 400 {
				return nil, status.New(statusError.Code(), statusError.Message()).Err()
			} else if statusError.Code() == 401 {
				return nil, status.New(statusError.Code(), "Логин и/или пароль не совпадают").Err()
			}
		}
		return nil, err
	}
	data := jwt.MapClaims{
		"username":    username,
		"role":        "student",
		"accessToken": response.Token,
		"exp":         time.Now().Add(time.Hour * 9).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, data)
	tokenString, err := token.SignedString([]byte(s.cfg.Service.Secret))
	if err != nil {
		return nil, err
	}
	return &auth_proto.LoginResponse{Jwt: tokenString}, nil
}

func MustAuthService(cfg *config.Config) *AuthService {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.Service.Port))
	if err != nil {
		log.Fatalf("Cannnot listen port: %s; Error: %s", cfg.Service.Port, err)
	}
	s := grpc.NewServer()
	service := &AuthService{cfg: cfg, Lis: lis, Server: s}
	auth_proto.RegisterAuthServiceServer(s, service)
	return service
}
