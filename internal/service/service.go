package service

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	auth_proto "github.com/s21platform/auth-proto/auth-proto"
	"github.com/s21platform/auth-service/internal/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strings"
	"time"
)

type Server struct {
	auth_proto.UnimplementedAuthServiceServer
	cfg        *config.Config
	communityS CommunityS
	schoolS    SchoolS
	redisR     RedisR
}

func (s *Server) Login(ctx context.Context, req *auth_proto.LoginRequest) (*auth_proto.LoginResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	fmt.Println(md.Get("trace-id"))
	username := req.Username
	if !strings.HasSuffix(req.Username, "@student.21-school.ru") {
		username += "@student.21-school.ru"
	}
	is, err := s.communityS.CheckPeer(ctx, username)
	if err != nil {
		return nil, err
	}

	if !is {
		return nil, status.Errorf(codes.FailedPrecondition, "Вы не являетесь участником s21")
	}

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

func New(cfg *config.Config, schoolService SchoolS, communityService CommunityS, redis RedisR) *Server {
	return &Server{
		cfg:        cfg,
		schoolS:    schoolService,
		communityS: communityService,
		redisR:     redis,
	}
}
