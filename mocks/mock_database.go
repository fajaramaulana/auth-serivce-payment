package mocks

import "github.com/stretchr/testify/mock"

// MockDatabase is a mock implementation of the Database interface for testing.
type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) Close() error {
	args := m.Called()
	return args.Error(0)
}
