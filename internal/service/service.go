package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/matthewhartstonge/argon2"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	logger_lib "github.com/s21platform/logger-lib"

	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/internal/model"
	"github.com/s21platform/auth-service/internal/pkg/tx"
	"github.com/s21platform/auth-service/pkg/auth"
)

type Service struct {
	auth.UnimplementedAuthServiceServer
	repository          DBRepo
	schoolS             SchoolS
	communityS          CommunityS
	notificationS       NotificationS
	searchKafkaProducer KafkaProducer
	userS               UserS
	secrets             config.Service
}

func New(repository DBRepo, schoolService SchoolS, communityService CommunityS, userService UserS, notificationService NotificationS, searchKafkaProducer KafkaProducer, secrets config.Service) *Service {
	return &Service{
		repository:          repository,
		schoolS:             schoolService,
		communityS:          communityService,
		notificationS:       notificationService,
		userS:               userService,
		searchKafkaProducer: searchKafkaProducer,
		secrets:             secrets,
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
		logger.Error(fmt.Sprintf("failed to get (or set) user into user-service: %v", err))
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
	tokenString, err := token.SignedString([]byte(s.secrets.Secret))
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

	email := strings.TrimSpace(in.Email)
	if email == "" {
		logger.Error("email is required")
		return nil, status.Errorf(codes.InvalidArgument, "email is required")
	}
	if len(email) > 100 {
		logger.Error("email exceeds maximum length of 100 characters")
		return nil, status.Errorf(codes.InvalidArgument, "email exceeds maximum length of 100 characters")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`).MatchString(email) {
		logger.Error("invalid email format")
		return nil, status.Errorf(codes.InvalidArgument, "invalid email format")
	}
	email = strings.ToLower(email)

	isAvailable, err := s.repository.IsEmailAvailable(ctx, email)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to check email: %v", err))
		return nil, err
	}

	return &auth.CheckEmailAvailabilityOut{IsAvailable: isAvailable}, nil
}

func (s *Service) SendUserVerificationCode(ctx context.Context, in *auth.SendUserVerificationCodeIn) (*auth.SendUserVerificationCodeOut, error) {
	logger := logger_lib.FromContext(ctx, config.KeyLogger)
	logger.AddFuncName("SendUserVerificationCode")

	// todo добавить rate limiter

	email := strings.TrimSpace(in.Email)
	if email == "" {
		logger.Error("email is required")
		return nil, status.Errorf(codes.InvalidArgument, "email is required")
	}
	if len(email) > 100 {
		logger.Error("email exceeds maximum length of 100 characters")
		return nil, status.Errorf(codes.InvalidArgument, "email exceeds maximum length of 100 characters")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`).MatchString(email) {
		logger.Error("invalid email format")
		return nil, status.Errorf(codes.InvalidArgument, "invalid email format")
	}
	email = strings.ToLower(email)

	codeInt, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		logger.Error(fmt.Sprintf("failed to generate verification code: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to generate code: %v", err)
	}
	code := fmt.Sprintf("%06d", codeInt)

	err = s.notificationS.SendVerificationCode(ctx, email, code)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to send verification code: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to send code: %v", err)
	}

	uuid, err := s.repository.InsertPendingRegistration(ctx, email, code)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to insert pending registration: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to add user to pending table: %v", err)
	}

	return &auth.SendUserVerificationCodeOut{Uuid: uuid}, nil
}

func (s *Service) RegisterUser(ctx context.Context, in *auth.RegisterUserIn) (*emptypb.Empty, error) {
	logger := logger_lib.FromContext(ctx, config.KeyLogger)
	logger.AddFuncName("RegisterUser")

	// todo добавить rate limiter

	email := strings.TrimSpace(in.Email)
	if email == "" {
		logger.Error("email is required")
		return nil, status.Errorf(codes.InvalidArgument, "email is required")
	}
	if len(email) > 100 {
		logger.Error("email exceeds maximum length of 100 characters")
		return nil, status.Errorf(codes.InvalidArgument, "email exceeds maximum length of 100 characters")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`).MatchString(email) {
		logger.Error("invalid email format")
		return nil, status.Errorf(codes.InvalidArgument, "invalid email format")
	}
	email = strings.ToLower(email)

	originalCode, err := s.repository.GetVerificationCode(ctx, in.CodeLookupUuid)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to get verification code: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to get verification code: %v", err)
	}

	if originalCode != in.Code {
		logger.Error("verification code is invalid")
		return nil, status.Errorf(codes.InvalidArgument, "verification code is invalid")
	}

	if in.Password != in.ConfirmPassword {
		logger.Error("various passwords")
		return nil, status.Errorf(codes.InvalidArgument, "various passwords")
	}

	salt := make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to generate salt: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to generate salt: %v", err)
	}

	saltedPassword := append([]byte(in.Password), salt...)
	hashedPassword, err := bcrypt.GenerateFromPassword(saltedPassword, bcrypt.DefaultCost)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to hash password: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to hash password: %v", err)
	}

	resp, err := s.userS.CreateUser(ctx, email)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create new user at user-service: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to create new user at user-service: %v", err)
	}

	err = tx.TxExecute(ctx, func(ctx context.Context) error {
		platformAccount := model.PlatformAccount{
			UserUUID:      resp.UserUuid,
			Nickname:      resp.Nickname,
			Email:         email,
			PasswordHash:  string(hashedPassword),
			PasswordSalt:  base64.StdEncoding.EncodeToString(salt),
			HashAlgorithm: "bcrypt+salt",
		}
		err = s.repository.SaveNewUser(ctx, &platformAccount)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to save new user into db: %v", err))
			return err
		}

		msg := &auth.NewUserRegister{
			Uuid:     resp.UserUuid,
			Nickname: resp.Nickname,
		}
		err = s.searchKafkaProducer.ProduceMessage(ctx, msg, resp.UserUuid)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to produce message: %v", err))
			return err
		}

		return nil
	})
	if err != nil {
		logger.Error(fmt.Sprintf("failed to complete transaction: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to complete transaction: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (s *Service) LoginV2(ctx context.Context, in *auth.LoginV2In) (*auth.LoginV2Out, error) {
	logger := logger_lib.FromContext(ctx, config.KeyLogger)
	logger.AddFuncName("LoginV2")

	// todo добавить rate limiter

	in.Login = strings.TrimSpace(in.Login)
	in.Login = strings.ToLower(in.Login)

	if in.Login == "" {
		logger.Error("login is empty")
		return nil, status.Errorf(codes.InvalidArgument, "login is empty")
	}

	if regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`).MatchString(in.Login) {
		return s.loginByEmail(ctx, in)
	}

	user, err := s.repository.GetUserByNickname(ctx, in.Login)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to get user by nickname %v", err))
		return nil, status.Errorf(codes.Internal, "failed to get user by nickname")
	}

	salt, err := base64.StdEncoding.DecodeString(user.PasswordSalt)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to decode password salt %v", err))
		return nil, status.Errorf(codes.Internal, "invalid password salt")
	}

	saltedPassword := append([]byte(in.Password), salt...)
	if err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), saltedPassword); err != nil {
		// todo добавить функционал блокировки пользователей после n неверных паролей
		logger.Error("invalid password")
		return nil, status.Errorf(codes.InvalidArgument, "invalid password")
	}

	refreshClaims := jwt.MapClaims{
		"sub":  user.UserUUID,
		"exp":  time.Now().Add(30 * 24 * time.Hour).Unix(),
		"iat":  time.Now().Unix(),
		"type": "refresh",
	}
	refreshJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err := refreshJWT.SignedString([]byte(s.secrets.RefreshSecret))
	if err != nil {
		logger.Error(fmt.Sprintf("failed to sign refresh JWT: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to sign refresh JWT: %v", err)
	}

	argon := argon2.DefaultConfig()
	hashedRefreshToken, err := argon.HashEncoded([]byte(refreshToken))
	if err != nil {
		logger.Error(fmt.Sprintf("failed to hash refresh token: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to hash refresh token: %v", err)
	}

	// todo убрать заглушки в будущем
	userAgent := "user-agent"
	userIP := "ip"
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if agents := md.Get("user-agent"); len(agents) > 0 {
			userAgent = agents[0]
		}
		if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
			userIP = ips[0]
		}
	}

	sessionCreds := model.Session{
		UserUUID:         user.UserUUID,
		RefreshTokenHash: string(hashedRefreshToken),
		UserAgent:        userAgent,
		IP:               userIP,
	}
	sessionId, err := s.repository.CreateSession(ctx, &sessionCreds)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create session: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to create session: %v", err)
	}

	accessClaims := jwt.MapClaims{
		"sid":      sessionId,
		"sub":      user.UserUUID,
		"nickname": user.Nickname,
		"exp":      time.Now().Add(15 * time.Minute).Unix(),
		"iat":      time.Now().Unix(),
		"type":     "access",
	}
	accessJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err := accessJWT.SignedString([]byte(s.secrets.AccessSecret))
	if err != nil {
		logger.Error(fmt.Sprintf("failed to sign access JWT: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to sign access JWT: %v", err)
	}

	return &auth.LoginV2Out{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Service) loginByEmail(ctx context.Context, in *auth.LoginV2In) (*auth.LoginV2Out, error) {
	logger := logger_lib.FromContext(ctx, config.KeyLogger)
	logger.AddFuncName("loginByEmail")

	if len(in.Login) > 100 {
		logger.Error("email exceeds maximum length of 100 characters")
		return nil, status.Errorf(codes.InvalidArgument, "email exceeds maximum length of 100 characters")
	}

	user, err := s.repository.GetUserByEmail(ctx, in.Login)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to get user by email %v", err))
		return nil, status.Errorf(codes.Internal, "failed to get user by email")
	}

	salt, err := base64.StdEncoding.DecodeString(user.PasswordSalt)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to decode password salt %v", err))
		return nil, status.Errorf(codes.Internal, "invalid password salt")
	}

	saltedPassword := append([]byte(in.Password), salt...)
	if err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), saltedPassword); err != nil {
		// todo добавить функционал блокировки пользователей после n неверных паролей
		logger.Error("invalid password")
		return nil, status.Errorf(codes.InvalidArgument, "invalid password")
	}

	refreshClaims := jwt.MapClaims{
		"sub":  user.UserUUID,
		"exp":  time.Now().Add(30 * 24 * time.Hour).Unix(),
		"iat":  time.Now().Unix(),
		"type": "refresh",
	}
	refreshJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err := refreshJWT.SignedString([]byte(s.secrets.RefreshSecret))
	if err != nil {
		logger.Error(fmt.Sprintf("failed to sign refresh JWT: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to sign refresh JWT: %v", err)
	}

	argon := argon2.DefaultConfig()
	hashedRefreshToken, err := argon.HashEncoded([]byte(refreshToken))
	if err != nil {
		logger.Error(fmt.Sprintf("failed to hash refresh token: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to hash refresh token: %v", err)
	}

	// todo убрать заглушки в будущем
	userAgent := "user-agent"
	userIP := "ip"
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if agents := md.Get("user-agent"); len(agents) > 0 {
			userAgent = agents[0]
		}
		if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
			userIP = ips[0]
		}
	}

	sessionCreds := model.Session{
		UserUUID:         user.UserUUID,
		RefreshTokenHash: string(hashedRefreshToken),
		UserAgent:        userAgent,
		IP:               userIP,
	}
	sessionId, err := s.repository.CreateSession(ctx, &sessionCreds)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create session: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to create session: %v", err)
	}

	accessClaims := jwt.MapClaims{
		"sid":      sessionId,
		"sub":      user.UserUUID,
		"nickname": user.Nickname,
		"exp":      time.Now().Add(15 * time.Minute).Unix(),
		"iat":      time.Now().Unix(),
		"type":     "access",
	}
	accessJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err := accessJWT.SignedString([]byte(s.secrets.AccessSecret))
	if err != nil {
		logger.Error(fmt.Sprintf("failed to sign access JWT: %v", err))
		return nil, status.Errorf(codes.Internal, "failed to sign access JWT: %v", err)
	}

	return &auth.LoginV2Out{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
