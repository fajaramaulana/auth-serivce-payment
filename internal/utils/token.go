package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Access and Refresh Token expiry durations
const (
	AccessTokenExpiry  = 15 * time.Minute
	RefreshTokenExpiry = 7 * 24 * time.Hour // 7 days
)

// Custom Claims structure
type CustomClaims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

// CreateToken generates an access token and a refresh token for the given userID
func CreateToken(userID int, jwtSecret string) (accessTokenReturn string, refreshTokenReturn string, err error) {
	// Define access token claims
	accessTokenClaims := CustomClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessTokenString, err := accessToken.SignedString([]byte(jwtSecret)) // Convert to []byte
	if err != nil {
		return "", "", err
	}

	// Define refresh token claims
	refreshTokenClaims := CustomClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(RefreshTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(jwtSecret)) // Convert to []byte
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

// CheckToken validates the given token string
func CheckToken(tokenString string, jwtSecret string) (*CustomClaims, error) {
	// Parse the token with claims
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil // Convert jwtSecret to []byte here as well
	})

	if err != nil {
		return nil, fmt.Errorf("error checking token: %w", err)
	}

	// Check if the token is valid and has the right claims
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
