package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"
	logger_lib "github.com/s21platform/logger-lib"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/pkg/auth"
)

func TestServer_Login(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockDBRepo(ctrl)
	mockSchoolSrv := NewMockSchoolS(ctrl)
	mockCommunitySrv := NewMockCommunityS(ctrl)
	mockUserSrv := NewMockUserS(ctrl)
	mockNotificationS := NewMockNotificationS(ctrl)
	mockUserKafka := NewMockKafkaProducer(ctrl)
	cfgService := config.Service{
		Port:          "8080",
		Secret:        "secret",
		AccessSecret:  "access_secret",
		RefreshSecret: "refresh_secret",
		Name:          "auth_service",
	}

	mockLogger := logger_lib.NewMockLoggerInterface(ctrl)

	t.Run("should_ok_full_username", func(t *testing.T) {
		login := "garroshm@student.21-school.ru"
		nickname := "garroshm"
		password := "123"
		uuid := "123"
		accessToken := "school_access_token"

		mockLogger.EXPECT().AddFuncName("Login")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), login).Return(true, nil)
		mockSchoolSrv.EXPECT().DoLogin(gomock.Any(), nickname, password).Return(accessToken, nil)
		mockUserSrv.EXPECT().GetOrSetUser(gomock.Any(), login).Return(uuid, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		resp, err := s.Login(ctx, &auth.LoginRequest{
			Username: login,
			Password: password,
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.Jwt)

		// Verify JWT claims
		token, _ := jwt.Parse(resp.Jwt, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfgService.Secret), nil
		})
		claims, ok := token.Claims.(jwt.MapClaims)
		assert.True(t, ok)
		assert.Equal(t, login, claims["username"])
		assert.Equal(t, "student", claims["role"])
		assert.Equal(t, accessToken, claims["accessToken"])
		assert.Equal(t, uuid, claims["uid"])
	})

	t.Run("should_ok_short_username", func(t *testing.T) {
		login := "garroshm"
		fullLogin := "garroshm@student.21-school.ru"
		password := "123"
		uuid := "123"
		accessToken := "school_access_token"

		mockLogger.EXPECT().AddFuncName("Login")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), fullLogin).Return(true, nil)
		mockSchoolSrv.EXPECT().DoLogin(gomock.Any(), login, password).Return(accessToken, nil)
		mockUserSrv.EXPECT().GetOrSetUser(gomock.Any(), fullLogin).Return(uuid, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		resp, err := s.Login(ctx, &auth.LoginRequest{
			Username: login,
			Password: password,
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.Jwt)
	})

	t.Run("should_ok_uppercase_username", func(t *testing.T) {
		login := "GARROSHM"
		fullLogin := "garroshm@student.21-school.ru"
		password := "123"
		uuid := "123"
		accessToken := "school_access_token"

		mockLogger.EXPECT().AddFuncName("Login")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), fullLogin).Return(true, nil)
		mockSchoolSrv.EXPECT().DoLogin(gomock.Any(), strings.ToLower(login), password).Return(accessToken, nil)
		mockUserSrv.EXPECT().GetOrSetUser(gomock.Any(), fullLogin).Return(uuid, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		resp, err := s.Login(ctx, &auth.LoginRequest{
			Username: login,
			Password: password,
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.Jwt)
	})

	t.Run("should_fail_not_community_member", func(t *testing.T) {
		login := "garroshm@student.21-school.ru"

		mockLogger.EXPECT().AddFuncName("Login")
		mockLogger.EXPECT().Error(gomock.Any())
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), login).Return(false, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		resp, err := s.Login(ctx, &auth.LoginRequest{
			Username: login,
			Password: "123",
		})

		assert.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Contains(t, st.Message(), "Вы не являетесь участником s21")
	})

	t.Run("should_fail_school_login", func(t *testing.T) {
		login := "garroshm@student.21-school.ru"
		nickname := "garroshm"
		expectedErr := errors.New("invalid credentials")

		mockLogger.EXPECT().AddFuncName("Login")
		mockLogger.EXPECT().Error(gomock.Any())
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), login).Return(true, nil)
		mockSchoolSrv.EXPECT().DoLogin(gomock.Any(), nickname, "123").Return("", expectedErr)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		resp, err := s.Login(ctx, &auth.LoginRequest{
			Username: login,
			Password: "123",
		})

		assert.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "Неверный логин или пароль")
	})
}

func TestService_CheckEmailAvailability(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfgService := config.Service{
		Port:          "8080",
		Secret:        "secret",
		AccessSecret:  "access_secret",
		RefreshSecret: "refresh_secret",
		Name:          "auth_service",
	}

	mockRepo := NewMockDBRepo(ctrl)
	mockSchoolSrv := NewMockSchoolS(ctrl)
	mockCommunitySrv := NewMockCommunityS(ctrl)
	mockUserSrv := NewMockUserS(ctrl)
	mockNotificationS := NewMockNotificationS(ctrl)
	mockUserKafka := NewMockKafkaProducer(ctrl)
	mockLogger := logger_lib.NewMockLoggerInterface(ctrl)

	t.Run("should_return_available_email", func(t *testing.T) {
		email := "test@example.com"

		mockLogger.EXPECT().AddFuncName("CheckEmailAvailability")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockRepo.EXPECT().IsEmailAvailable(gomock.Any(), email).Return(true, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.CheckEmailAvailability(ctx, &auth.CheckEmailAvailabilityIn{
			Email: email,
		})

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.IsAvailable)
	})

	t.Run("should_return_unavailable_email", func(t *testing.T) {
		email := "used@example.com"

		mockLogger.EXPECT().AddFuncName("CheckEmailAvailability")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockRepo.EXPECT().IsEmailAvailable(gomock.Any(), email).Return(false, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.CheckEmailAvailability(ctx, &auth.CheckEmailAvailabilityIn{
			Email: email,
		})

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsAvailable)
	})

	t.Run("should_convert_email_to_lowercase", func(t *testing.T) {
		email := "TEST@EXAMPLE.COM"
		lowerEmail := "test@example.com"

		mockLogger.EXPECT().AddFuncName("CheckEmailAvailability")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockRepo.EXPECT().IsEmailAvailable(gomock.Any(), lowerEmail).Return(true, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.CheckEmailAvailability(ctx, &auth.CheckEmailAvailabilityIn{
			Email: email,
		})

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.IsAvailable)
	})

	t.Run("should_handle_empty_email", func(t *testing.T) {
		mockLogger.EXPECT().AddFuncName("CheckEmailAvailability")
		mockLogger.EXPECT().Error("email is required")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.CheckEmailAvailability(ctx, &auth.CheckEmailAvailabilityIn{
			Email: "",
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "email is required")
		assert.Nil(t, result)
	})

	t.Run("should_handle_invalid_email_format", func(t *testing.T) {
		email := "invalid-email"

		mockLogger.EXPECT().AddFuncName("CheckEmailAvailability")
		mockLogger.EXPECT().Error("invalid email format")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.CheckEmailAvailability(ctx, &auth.CheckEmailAvailabilityIn{
			Email: email,
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "invalid email format")
		assert.Nil(t, result)
	})

	t.Run("should_handle_long_email", func(t *testing.T) {
		email := strings.Repeat("a", 101)

		mockLogger.EXPECT().AddFuncName("CheckEmailAvailability")
		mockLogger.EXPECT().Error("email exceeds maximum length of 100 characters")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.CheckEmailAvailability(ctx, &auth.CheckEmailAvailabilityIn{
			Email: email,
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "email exceeds maximum length of 100 characters")
		assert.Nil(t, result)
	})

	t.Run("should_handle_repository_error", func(t *testing.T) {
		email := "test@example.com"
		expectedErr := errors.New("database error")

		mockLogger.EXPECT().AddFuncName("CheckEmailAvailability")
		mockLogger.EXPECT().Error(gomock.Any())
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockRepo.EXPECT().IsEmailAvailable(gomock.Any(), email).Return(false, expectedErr)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.CheckEmailAvailability(ctx, &auth.CheckEmailAvailabilityIn{
			Email: email,
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database error")
		assert.Nil(t, result)
	})
}

func TestService_SendUserVerificationCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfgService := config.Service{
		Port:          "8080",
		Secret:        "secret",
		AccessSecret:  "access_secret",
		RefreshSecret: "refresh_secret",
		Name:          "auth_service",
	}

	mockRepo := NewMockDBRepo(ctrl)
	mockSchoolSrv := NewMockSchoolS(ctrl)
	mockCommunitySrv := NewMockCommunityS(ctrl)
	mockUserSrv := NewMockUserS(ctrl)
	mockNotificationS := NewMockNotificationS(ctrl)
	mockUserKafka := NewMockKafkaProducer(ctrl)
	mockLogger := logger_lib.NewMockLoggerInterface(ctrl)

	t.Run("should_send_verification_code", func(t *testing.T) {
		email := "test@example.com"
		uuid := "test-uuid"

		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockNotificationS.EXPECT().SendVerificationCode(gomock.Any(), email, gomock.Any()).Return(nil)
		mockRepo.EXPECT().InsertPendingRegistration(gomock.Any(), email, gomock.Any()).Return(uuid, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: email,
		})

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, uuid, result.Uuid)
	})

	t.Run("should_convert_email_to_lowercase", func(t *testing.T) {
		email := "TEST@EXAMPLE.COM"
		lowerEmail := "test@example.com"
		uuid := "test-uuid"

		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockNotificationS.EXPECT().SendVerificationCode(gomock.Any(), lowerEmail, gomock.Any()).Return(nil)
		mockRepo.EXPECT().InsertPendingRegistration(gomock.Any(), lowerEmail, gomock.Any()).Return(uuid, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: email,
		})

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, uuid, result.Uuid)
	})

	t.Run("should_handle_empty_email", func(t *testing.T) {
		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		mockLogger.EXPECT().Error("email is required")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: "",
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "email is required")
		assert.Nil(t, result)
	})

	t.Run("should_handle_invalid_email", func(t *testing.T) {
		email := "invalid-email"

		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		mockLogger.EXPECT().Error("invalid email format")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: email,
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "invalid email format")
		assert.Nil(t, result)
	})

	t.Run("should_handle_long_email", func(t *testing.T) {
		email := strings.Repeat("a", 101)

		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		mockLogger.EXPECT().Error("email exceeds maximum length of 100 characters")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: email,
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "email exceeds maximum length of 100 characters")
		assert.Nil(t, result)
	})

	t.Run("should_handle_notification_error", func(t *testing.T) {
		email := "test@example.com"
		expectedErr := errors.New("notification error")

		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		mockLogger.EXPECT().Error(gomock.Any())
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockNotificationS.EXPECT().SendVerificationCode(gomock.Any(), email, gomock.Any()).Return(expectedErr)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: email,
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Contains(t, st.Message(), "notification error")
		assert.Nil(t, result)
	})

	t.Run("should_handle_repository_error", func(t *testing.T) {
		email := "test@example.com"
		expectedErr := errors.New("database error")

		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		mockLogger.EXPECT().Error(gomock.Any())
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockNotificationS.EXPECT().SendVerificationCode(gomock.Any(), email, gomock.Any()).Return(nil)
		mockRepo.EXPECT().InsertPendingRegistration(gomock.Any(), email, gomock.Any()).Return("", expectedErr)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, mockUserKafka, cfgService)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: email,
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Contains(t, st.Message(), "database error")
		assert.Nil(t, result)
	})
}
