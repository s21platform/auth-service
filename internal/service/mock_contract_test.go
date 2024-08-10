// Code generated by MockGen. DO NOT EDIT.
// Source: contract.go

// Package service is a generated GoMock package.
package service

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockSchoolS is a mock of SchoolS interface.
type MockSchoolS struct {
	ctrl     *gomock.Controller
	recorder *MockSchoolSMockRecorder
}

// MockSchoolSMockRecorder is the mock recorder for MockSchoolS.
type MockSchoolSMockRecorder struct {
	mock *MockSchoolS
}

// NewMockSchoolS creates a new mock instance.
func NewMockSchoolS(ctrl *gomock.Controller) *MockSchoolS {
	mock := &MockSchoolS{ctrl: ctrl}
	mock.recorder = &MockSchoolSMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSchoolS) EXPECT() *MockSchoolSMockRecorder {
	return m.recorder
}

// DoLogin mocks base method.
func (m *MockSchoolS) DoLogin(ctx context.Context, email, password string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DoLogin", ctx, email, password)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DoLogin indicates an expected call of DoLogin.
func (mr *MockSchoolSMockRecorder) DoLogin(ctx, email, password interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DoLogin", reflect.TypeOf((*MockSchoolS)(nil).DoLogin), ctx, email, password)
}

// MockCommunityS is a mock of CommunityS interface.
type MockCommunityS struct {
	ctrl     *gomock.Controller
	recorder *MockCommunitySMockRecorder
}

// MockCommunitySMockRecorder is the mock recorder for MockCommunityS.
type MockCommunitySMockRecorder struct {
	mock *MockCommunityS
}

// NewMockCommunityS creates a new mock instance.
func NewMockCommunityS(ctrl *gomock.Controller) *MockCommunityS {
	mock := &MockCommunityS{ctrl: ctrl}
	mock.recorder = &MockCommunitySMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCommunityS) EXPECT() *MockCommunitySMockRecorder {
	return m.recorder
}

// CheckPeer mocks base method.
func (m *MockCommunityS) CheckPeer(ctx context.Context, email string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CheckPeer", ctx, email)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CheckPeer indicates an expected call of CheckPeer.
func (mr *MockCommunitySMockRecorder) CheckPeer(ctx, email interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckPeer", reflect.TypeOf((*MockCommunityS)(nil).CheckPeer), ctx, email)
}

// MockRedisR is a mock of RedisR interface.
type MockRedisR struct {
	ctrl     *gomock.Controller
	recorder *MockRedisRMockRecorder
}

// MockRedisRMockRecorder is the mock recorder for MockRedisR.
type MockRedisRMockRecorder struct {
	mock *MockRedisR
}

// NewMockRedisR creates a new mock instance.
func NewMockRedisR(ctrl *gomock.Controller) *MockRedisR {
	mock := &MockRedisR{ctrl: ctrl}
	mock.recorder = &MockRedisRMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRedisR) EXPECT() *MockRedisRMockRecorder {
	return m.recorder
}

// Get mocks base method.
func (m *MockRedisR) Get() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Get")
}

// Get indicates an expected call of Get.
func (mr *MockRedisRMockRecorder) Get() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockRedisR)(nil).Get))
}

// Set mocks base method.
func (m *MockRedisR) Set() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Set")
}

// Set indicates an expected call of Set.
func (mr *MockRedisRMockRecorder) Set() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Set", reflect.TypeOf((*MockRedisR)(nil).Set))
}
