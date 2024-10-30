package mocks

import "github.com/stretchr/testify/mock"

// MockConfig is a mock struct for config.Config
type MockConfig struct {
	mock.Mock
}

// Get is a mock method for config.Config's Get method
func (m *MockConfig) Get(key string) string {
	args := m.Called(key)
	return args.String(0)
}
