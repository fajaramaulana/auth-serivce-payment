package utils_test

import (
	"testing"
	"time"

	"github.com/fajaramaulana/auth-serivce-payment/internal/utils"
	"github.com/fajaramaulana/auth-serivce-payment/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestBcryptHasher_Generate(t *testing.T) {
	hasher := utils.BcryptHasher{}

	tests := []struct {
		name      string
		password  []byte
		cost      int
		expectErr bool
	}{
		{
			name:      "Valid password and cost",
			password:  []byte("strong_password"),
			cost:      bcrypt.DefaultCost,
			expectErr: false,
		},
		{
			name:      "Short password",
			password:  []byte("123"),
			cost:      bcrypt.DefaultCost,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashedPassword, err := hasher.Generate(tt.password, tt.cost)

			if tt.expectErr {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.NotNil(t, hashedPassword, "Expected a hashed password")
				assert.Greater(t, len(hashedPassword), 0, "Expected a non-empty hash")

				// Verify the hash matches the original password
				assert.NoError(t, bcrypt.CompareHashAndPassword(hashedPassword, tt.password), "Password hash does not match")
			}
		})
	}
}

func TestNewPasswordHasher(t *testing.T) {
	// Call the function
	hasher := utils.NewPasswordHasher()

	// Check if the returned hasher is of type BcryptHasher
	_, ok := hasher.(utils.BcryptHasher)
	assert.True(t, ok, "NewPasswordHasher should return a BcryptHasher type")
}

func TestTimeMustParse(t *testing.T) {
	tests := []struct {
		name         string
		layout       string
		expectPanic  bool
		expectedTime time.Time
	}{
		{
			name:         "Valid date format",
			layout:       "2024-10-30",
			expectPanic:  false,
			expectedTime: time.Date(2024, 10, 30, 0, 0, 0, 0, time.UTC),
		},
		{
			name:        "Invalid date format",
			layout:      "30-10-2024",
			expectPanic: true,
		},
		{
			name:        "Empty date string",
			layout:      "",
			expectPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectPanic {
				assert.Panics(t, func() {
					utils.TimeMustParse(tt.layout)
				}, "Expected a panic but function did not panic")
			} else {
				result := utils.TimeMustParse(tt.layout)
				require.NotNil(t, result)
				assert.Equal(t, tt.expectedTime, result, "Parsed time does not match expected time")
			}
		})
	}
}

func TestTokenHandler_CreateAndCheckToken(t *testing.T) {
	// Mock configuration setup
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "JWT_SECRET").Return("test_secret_key")

	// Initialize the TokenHandler with the mock config
	tokenHandler := utils.NewTokenHandler(mockConfig)

	// Test data
	userID := 123

	// Test CreateToken
	accessToken, refreshToken, err := tokenHandler.CreateToken(userID)
	assert.NoError(t, err, "Expected no error when creating tokens")
	assert.NotEmpty(t, accessToken, "Access token should not be empty")
	assert.NotEmpty(t, refreshToken, "Refresh token should not be empty")

	// Test CheckToken with Access Token
	claims, err := tokenHandler.CheckToken(accessToken)
	assert.NoError(t, err, "Expected no error when checking access token")
	assert.NotNil(t, claims, "Expected valid claims from access token")
	assert.Equal(t, userID, claims.UserID, "UserID should match the one used to create the token")

	// Test CheckToken with Refresh Token
	claims, err = tokenHandler.CheckToken(refreshToken)
	assert.NoError(t, err, "Expected no error when checking refresh token")
	assert.NotNil(t, claims, "Expected valid claims from refresh token")
	assert.Equal(t, userID, claims.UserID, "UserID should match the one used to create the token")

	// Verify all expectations were met
	mockConfig.AssertExpectations(t)
}
