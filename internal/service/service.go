package service

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	auth_proto "github.com/s21platform/auth-proto/auth-proto"
	"github.com/s21platform/auth-service/internal/config"
	"google.golang.org/grpc/metadata"
	"strings"
	"time"
)

type Server struct {
	auth_proto.UnimplementedAuthServiceServer
	cfg     *config.Config
	schoolS SchoolS
	redisR  RedisR
}

func (s *Server) Login(ctx context.Context, req *auth_proto.LoginRequest) (*auth_proto.LoginResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	fmt.Println(md.Get("trace-id"))
	username := req.Username
	if !strings.HasSuffix(req.Username, "@student.21-school.ru") {
		username += "@student.21-school.ru"
	}
	// TODO делать запрос в community rpc для уточнения студент ли пользователь
	t, err := s.schoolS.DoLogin(ctx, username, req.Password)
	if err != nil {
		return nil, err
	}
	data := jwt.MapClaims{
		"username":    username,
		"role":        "student",
		"accessToken": t,
		"exp":         time.Now().Add(time.Hour * 9).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, data)
	tokenString, err := token.SignedString([]byte(s.cfg.Service.Secret))
	if err != nil {
		return nil, err
	}
	return &auth_proto.LoginResponse{Jwt: tokenString}, nil
}

func New(cfg *config.Config, schoolService SchoolS, redis RedisR) *Server {
	return &Server{
		cfg:     cfg,
		schoolS: schoolService,
		redisR:  redis,
	}
}
