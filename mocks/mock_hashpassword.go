package mocks

import "github.com/stretchr/testify/mock"

// mocks.MockPasswordHasher.go
type MockPasswordHasher struct {
	mock.Mock
}

// Implement the Generate method to match the actual password hashing function signature
func (m *MockPasswordHasher) Generate(password []byte, cost int) ([]byte, error) {
	args := m.Called(password, cost)
	if arg := args.Get(0); arg != nil {
		return arg.([]byte), args.Error(1)
	}
	return nil, args.Error(1) // Ensure this returns nil and the error
}
