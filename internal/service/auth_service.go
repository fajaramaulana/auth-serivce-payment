package service

import (
	"context"

	"github.com/fajaramaulana/shared-proto-payment/proto/auth"
)

type AuthService interface {
	LoginUser(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error)
	RegisterUser(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error)
	RefreshToken(ctx context.Context, req *auth.RefreshTokenRequest) (*auth.RefreshTokenResponse, error)
}
