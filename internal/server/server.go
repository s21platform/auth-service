package server

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	auth_proto "github.com/s21platform/auth-proto/auth-proto"
	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/internal/service/school"
	school_proto "github.com/s21platform/school-proto/school-proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"net"
	"strings"
	"time"
)

type Server struct {
	auth_proto.UnimplementedAuthServiceServer
	cfg           *config.Config
	schoolService school.Service
}

func (s *Server) Login(ctx context.Context, req *auth_proto.LoginRequest) (*auth_proto.LoginResponse, error) {
	fmt.Println("Login request")
	username := req.Username
	if !strings.HasSuffix(req.Username, "@student.21-school.ru") {
		username += "@student.21-school.ru"
	}
	resp, err := s.schoolService.Client.Login(ctx, &school_proto.SchoolLoginRequest{Email: username, Password: req.Password})
	if err != nil {
		if statusError, ok := status.FromError(err); ok {
			if statusError.Code() == codes.Unavailable {
				return nil, status.Error(codes.Unavailable, "School service is offline")
			}
			if statusError.Code() == codes.InvalidArgument {
				return nil, status.Error(codes.InvalidArgument, "School service is offline")
			}
			return nil, err
		}
	}
	data := jwt.MapClaims{
		"username":    username,
		"role":        "student",
		"accessToken": resp.Token,
		"exp":         time.Now().Add(time.Hour * 9).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, data)
	tokenString, err := token.SignedString([]byte(s.cfg.Service.Secret))
	if err != nil {
		return nil, err
	}
	return &auth_proto.LoginResponse{Jwt: tokenString}, nil
}

func (s *Server) CloseConn() {
	s.schoolService.Conn.Close()
}

func (s *Server) Run() {
	defer s.CloseConn()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", s.cfg.Service.Port))
	if err != nil {
		log.Fatalf("Cannnot listen port: %s; Error: %s", s.cfg.Service.Port, err)
	}
	server := grpc.NewServer()
	auth_proto.RegisterAuthServiceServer(server, s)
	log.Println("Starting server", s.cfg.Service.Port)
	if err := server.Serve(lis); err != nil {
		log.Fatalf("Cannnot start server: %s; Error: %s", s.cfg.Service.Port, err)
	}
}

func NewServer(cfg *config.Config) *Server {
	SchoolService := school.MustConnect(cfg)
	return &Server{
		cfg:           cfg,
		schoolService: *SchoolService,
	}
}
