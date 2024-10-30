package mocks

import (
	"database/sql"

	"github.com/fajaramaulana/auth-serivce-payment/internal/model"
	"github.com/stretchr/testify/mock"
)

type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) CheckRefreshToken(userId int, refreshToken string) (bool, error) {
	args := m.Called(userId, refreshToken)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) CheckUserByEmailRegister(email string) (bool, error) {
	args := m.Called(email)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) CheckUserByUsernameRegister(username string) (bool, error) {
	args := m.Called(username)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) CreateUser(user *model.UserRegister) (result sql.Result, err error) {
	args := m.Called(user)
	return args.Get(0).(sql.Result), args.Error(1)
}

func (m *MockRepository) UpdateRefreshToken(UserId int, refreshToken string) error {
	args := m.Called(UserId, refreshToken)
	return args.Error(0)
}

func (m *MockRepository) DeleteRefreshToken(UserId int, refreshToken string) error {
	args := m.Called(UserId, refreshToken)
	return args.Error(0)
}

func (m *MockRepository) FindUserByEmail(email string) (*model.GetUserPassword, error) {
	args := m.Called(email)
	return args.Get(0).(*model.GetUserPassword), args.Error(1)
}

func (m *MockRepository) FindUserByUsername(username string) (*model.GetUserPassword, error) {
	args := m.Called(username)
	return args.Get(0).(*model.GetUserPassword), args.Error(1)
}
