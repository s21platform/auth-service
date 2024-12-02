package service

import (
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	auth_proto "github.com/s21platform/auth-proto/auth-proto"
	"github.com/s21platform/auth-service/internal/config"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestServer_Login(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Service: config.Service{
			Secret: "test",
		},
	}
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockSchoolSrv := NewMockSchoolS(ctrl)
	mockCommunitySrv := NewMockCommunityS(ctrl)
	MockRedisRepo := NewMockRedisR(ctrl)
	mockUserSrv := NewMockUserService(ctrl)

	t.Run("should_ok_full_username", func(t *testing.T) {
		login := "garroshm@student.21-school.ru"
		nickname := "garroshm"
		password := "123"
		uuid := "123"

		mockSchoolSrv.EXPECT().DoLogin(gomock.Any(), nickname, password).Return("123", nil)
		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), login).Return(true, nil)
		mockUserSrv.EXPECT().GetOrSetUser(gomock.Any(), login).Return(uuid, nil)

		s := New(cfg, mockSchoolSrv, mockCommunitySrv, MockRedisRepo, mockUserSrv)
		_, err := s.Login(ctx, &auth_proto.LoginRequest{
			Username: login,
			Password: password,
		})
		assert.NoError(t, err)
	})

	t.Run("should_ok_short_username", func(t *testing.T) {
		login := "garroshm"
		password := "123"

		mockSchoolSrv.EXPECT().DoLogin(gomock.Any(), login, password).Return("123", nil)
		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), login+"@student.21-school.ru").Return(true, nil)
		mockUserSrv.EXPECT().GetOrSetUser(gomock.Any(), login+"@student.21-school.ru").Return("123", nil)

		s := New(cfg, mockSchoolSrv, mockCommunitySrv, MockRedisRepo, mockUserSrv)
		_, err := s.Login(ctx, &auth_proto.LoginRequest{
			Username: login,
			Password: password,
		})
		assert.NoError(t, err)
	})

	t.Run("should_ok_short_username_upper", func(t *testing.T) {
		login := "garroshm"
		password := "123"

		mockSchoolSrv.EXPECT().DoLogin(gomock.Any(), login, password).Return("123", nil)
		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), login+"@student.21-school.ru").Return(true, nil)
		mockUserSrv.EXPECT().GetOrSetUser(gomock.Any(), login+"@student.21-school.ru").Return("123", nil)

		s := New(cfg, mockSchoolSrv, mockCommunitySrv, MockRedisRepo, mockUserSrv)
		_, err := s.Login(ctx, &auth_proto.LoginRequest{
			Username: strings.ToUpper(login),
			Password: password,
		})
		assert.NoError(t, err)
	})

	t.Run("should_ok_short_username", func(t *testing.T) {
		err_ := errors.New("err")

		mockCommunitySrv.EXPECT().CheckPeer(gomock.Any(), gomock.Any()).Return(true, err_)

		s := New(cfg, mockSchoolSrv, mockCommunitySrv, MockRedisRepo, mockUserSrv)
		_, err := s.Login(ctx, &auth_proto.LoginRequest{})
		assert.Equal(t, err, err_)
	})

}
