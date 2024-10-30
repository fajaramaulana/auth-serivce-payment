package mocks

import (
	"github.com/fajaramaulana/auth-serivce-payment/internal/utils"
	"github.com/stretchr/testify/mock"
)

type MockTokenHandler struct {
	mock.Mock
}

func (m *MockTokenHandler) CreateToken(userID int) (string, string, error) {
	args := m.Called(userID)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockTokenHandler) CheckToken(tokenString string) (*utils.CustomClaims, error) {
	args := m.Called(tokenString)
	return args.Get(0).(*utils.CustomClaims), args.Error(1)
}
