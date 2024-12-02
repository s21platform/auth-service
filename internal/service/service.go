package service

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	auth_proto "github.com/s21platform/auth-proto/auth-proto"
	"github.com/s21platform/auth-service/internal/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
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
	//md, _ := metadata.FromIncomingContext(ctx)
	//fmt.Println(md.Get("trace-id"))
	username := req.Username
	if !strings.HasSuffix(req.Username, "@student.21-school.ru") {
		username += "@student.21-school.ru"
	} else {
		req.Username = strings.ReplaceAll(req.Username, "@student.21-school.ru", "")
	}

	is, err := s.communityS.CheckPeer(ctx, username)
	if err != nil {
		log.Println("Error checking user", err)
		return nil, err
	}

	if !is {
		log.Println("User isn't a community")
		return nil, status.Errorf(codes.FailedPrecondition, "Вы не являетесь участником s21")
	}

	t, err := s.schoolS.DoLogin(ctx, req.Username, req.Password)
	if err != nil {
		log.Println("Error do login", err)
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
		log.Println("Error signing token", err)
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
