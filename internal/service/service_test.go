package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	logger_lib "github.com/s21platform/logger-lib"

	"github.com/s21platform/auth-service/internal/config"
	"github.com/s21platform/auth-service/pkg/auth"
)

func TestServer_Login(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	secret := "secret"

	mockRepo := NewMockDBRepo(ctrl)
	mockSchoolSrv := NewMockSchoolS(ctrl)
	mockCommunitySrv := NewMockCommunityS(ctrl)
	mockUserSrv := NewMockUserS(ctrl)
	mockNotificationS := NewMockNotificationS(ctrl)

	mockLogger := logger_lib.NewMockLoggerInterface(ctrl)

	t.Run("should_ok_full_username", func(t *testing.T) {
		login := "garroshm@student.21-school.ru"
		nickname := "garroshm"
		password := "123"
		uuid := "123"

		mockLogger.EXPECT().AddFuncName("Login")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockSchoolSrv.EXPECT().DoLogin(gomock.Any(), nickname, password).Return("123", nil)
		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), login).Return(true, nil)
		mockUserSrv.EXPECT().GetOrSetUser(gomock.Any(), login).Return(uuid, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		_, err := s.Login(ctx, &auth.LoginRequest{
			Username: login,
			Password: password,
		})
		assert.NoError(t, err)
	})

	t.Run("should_ok_short_username", func(t *testing.T) {
		login := "garroshm"
		password := "123"

		mockLogger.EXPECT().AddFuncName("Login")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockSchoolSrv.EXPECT().DoLogin(gomock.Any(), login, password).Return("123", nil)
		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), login+"@student.21-school.ru").Return(true, nil)
		mockUserSrv.EXPECT().GetOrSetUser(gomock.Any(), login+"@student.21-school.ru").Return("123", nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		_, err := s.Login(ctx, &auth.LoginRequest{
			Username: login,
			Password: password,
		})
		assert.NoError(t, err)
	})

	t.Run("should_ok_short_username_upper", func(t *testing.T) {
		login := "garroshm"
		password := "123"

		mockLogger.EXPECT().AddFuncName("Login")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockSchoolSrv.EXPECT().DoLogin(gomock.Any(), login, password).Return("123", nil)
		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), login+"@student.21-school.ru").Return(true, nil)
		mockUserSrv.EXPECT().GetOrSetUser(gomock.Any(), login+"@student.21-school.ru").Return("123", nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		_, err := s.Login(ctx, &auth.LoginRequest{
			Username: strings.ToUpper(login),
			Password: password,
		})
		assert.NoError(t, err)
	})

	t.Run("should_ok_short_username", func(t *testing.T) {
		err_ := errors.New("err")

		mockLogger.EXPECT().AddFuncName("Login")
		mockLogger.EXPECT().Error(gomock.Any())
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), gomock.Any()).Return(true, err_)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		_, err := s.Login(ctx, &auth.LoginRequest{})
		assert.Equal(t, err, err_)
	})
}

func TestService_CheckEmailAvailability(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	secret := "secret"

	mockRepo := NewMockDBRepo(ctrl)
	mockSchoolSrv := NewMockSchoolS(ctrl)
	mockCommunitySrv := NewMockCommunityS(ctrl)
	mockUserSrv := NewMockUserS(ctrl)
	mockNotificationS := NewMockNotificationS(ctrl)

	mockLogger := logger_lib.NewMockLoggerInterface(ctrl)

	t.Run("should_return_available_email", func(t *testing.T) {
		email := "test@example.com"

		mockLogger.EXPECT().AddFuncName("CheckEmailAvailability")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockRepo.EXPECT().IsEmailAvailable(gomock.Any(), email).Return(true, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
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

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
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

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		result, err := s.CheckEmailAvailability(ctx, &auth.CheckEmailAvailabilityIn{
			Email: email,
		})

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.IsAvailable)
	})

	t.Run("should_handle_repository_error", func(t *testing.T) {
		email := "test@example.com"
		expectedErr := errors.New("database error")

		mockLogger.EXPECT().AddFuncName("CheckEmailAvailability")
		mockLogger.EXPECT().Error(gomock.Any())
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockRepo.EXPECT().IsEmailAvailable(gomock.Any(), email).Return(false, expectedErr)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		result, err := s.CheckEmailAvailability(ctx, &auth.CheckEmailAvailabilityIn{
			Email: email,
		})

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.Nil(t, result)
	})

	t.Run("should_handle_empty_email", func(t *testing.T) {
		email := ""

		mockLogger.EXPECT().AddFuncName("CheckEmailAvailability")
		mockLogger.EXPECT().Error("email is required")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		result, err := s.CheckEmailAvailability(ctx, &auth.CheckEmailAvailabilityIn{
			Email: email,
		})

		assert.Error(t, err)
		assert.EqualError(t, err, "email is required")
		assert.Nil(t, result)
	})
}

func TestService_SendUserVerificationCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	secret := "secret"

	mockRepo := NewMockDBRepo(ctrl)
	mockSchoolSrv := NewMockSchoolS(ctrl)
	mockCommunitySrv := NewMockCommunityS(ctrl)
	mockUserSrv := NewMockUserS(ctrl)
	mockNotificationS := NewMockNotificationS(ctrl)

	mockLogger := logger_lib.NewMockLoggerInterface(ctrl)

	t.Run("should_add_pending_user_successfully", func(t *testing.T) {
		email := "test@example.com"
		expectedUUID := "test-uuid"

		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockNotificationS.EXPECT().SendVerificationCode(gomock.Any(), email, gomock.Any()).Return(nil)

		mockRepo.EXPECT().InsertPendingRegistration(gomock.Any(), email, gomock.Any()).Return(expectedUUID, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: email,
		})

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, expectedUUID, result.Uuid)
	})

	t.Run("should_convert_email_to_lowercase", func(t *testing.T) {
		email := "TEST@EXAMPLE.COM"
		lowerEmail := "test@example.com"
		expectedUUID := "test-uuid"

		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockNotificationS.EXPECT().SendVerificationCode(gomock.Any(), lowerEmail, gomock.Any()).Return(nil)

		mockRepo.EXPECT().InsertPendingRegistration(gomock.Any(), lowerEmail, gomock.Any()).Return(expectedUUID, nil)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: email,
		})

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, expectedUUID, result.Uuid)
	})

	t.Run("should_handle_empty_email", func(t *testing.T) {
		email := ""

		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		mockLogger.EXPECT().Error("email is required")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: email,
		})

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "email is required")
	})

	t.Run("should_handle_notification_service_error", func(t *testing.T) {
		email := "test@example.com"
		expectedErr := errors.New("notification service error")

		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockNotificationS.EXPECT().SendVerificationCode(gomock.Any(), email, gomock.Any()).Return(expectedErr)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: email,
		})

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to send code")
	})

	t.Run("should_handle_repository_error", func(t *testing.T) {
		email := "test@example.com"
		expectedErr := errors.New("database error")

		mockLogger.EXPECT().AddFuncName("SendUserVerificationCode")
		ctx := context.WithValue(ctx, config.KeyLogger, mockLogger)

		mockNotificationS.EXPECT().SendVerificationCode(gomock.Any(), email, gomock.Any()).Return(nil)

		mockRepo.EXPECT().InsertPendingRegistration(gomock.Any(), email, gomock.Any()).Return("", expectedErr)

		s := New(mockRepo, mockSchoolSrv, mockCommunitySrv, mockUserSrv, mockNotificationS, secret)
		result, err := s.SendUserVerificationCode(ctx, &auth.SendUserVerificationCodeIn{
			Email: email,
		})

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to add user to pending table")
	})
}
