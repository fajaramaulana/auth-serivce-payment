package service

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/fajaramaulana/auth-serivce-payment/internal/config"
	"github.com/fajaramaulana/auth-serivce-payment/internal/model"
	"github.com/fajaramaulana/auth-serivce-payment/internal/repository"
	"github.com/fajaramaulana/auth-serivce-payment/internal/utils"
	"github.com/fajaramaulana/shared-proto-payment/proto/auth"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type AuthServiceImpl struct {
	repo                                repository.UserRepository
	config                              config.Config
	auth.UnimplementedAuthServiceServer // embed by value
}

func NewAuthService(authRepo repository.UserRepository, config config.Config) auth.AuthServiceServer {
	return &AuthServiceImpl{
		repo:   authRepo,
		config: config,
	}
}

func (s *AuthServiceImpl) LoginUser(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	logrus.Infof("Login attempt for user: %s", req.GetUsername())
	// Find user by username
	user, err := s.repo.FindUserByUsername(req.GetUsername())
	if err != nil {
		logrus.Errorf("Error finding user: %v", err)
		return &auth.LoginResponse{Status: http.StatusUnauthorized, Message: "Invalid credentials", AccessToken: "", RefreshToken: ""}, nil
	}

	if user == nil {
		logrus.Warn("User not found")
		return &auth.LoginResponse{Status: http.StatusUnauthorized, Message: "Invalid credentials", AccessToken: "", RefreshToken: ""}, nil
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.GetPassword())); err != nil {
		logrus.Warn("Password mismatch")
		return &auth.LoginResponse{Status: http.StatusUnauthorized, Message: "Invalid credentials", AccessToken: "", RefreshToken: ""}, nil
	}

	accessToken, refreshToken, err := utils.CreateToken(user.ID, s.config.Get("JWT_SECRET"))
	if err != nil {
		logrus.Errorf("Error creating token: %v", err)
		return &auth.LoginResponse{Status: http.StatusInternalServerError, Message: "Internal server error", AccessToken: "", RefreshToken: ""}, nil
	}

	err = s.repo.UpdateRefreshToken(user.ID, refreshToken)
	if err != nil {
		logrus.Errorf("Error updating refresh token: %v", err)
		return &auth.LoginResponse{Status: http.StatusInternalServerError, Message: "Internal server error", AccessToken: "", RefreshToken: ""}, nil
	}

	logrus.Infof("User %s logged in successfully", req.GetUsername())
	return &auth.LoginResponse{Status: http.StatusOK, Message: "Login successful", AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s *AuthServiceImpl) RegisterUser(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	logrus.Infof("Registering user: %s", req.GetUsername())
	// Check if user already exists
	checkUsername, err := s.repo.CheckUserByUsernameRegister(req.GetUsername())
	if err != nil {
		logrus.Errorf("Error finding user: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	if checkUsername {
		logrus.Warn("Username already exists")
		return &auth.RegisterResponse{Status: http.StatusConflict, Message: "Username already exists", AccessToken: "", RefreshToken: ""}, nil
	}

	checkEmail, err := s.repo.CheckUserByEmailRegister(req.GetEmail())
	if err != nil {
		logrus.Errorf("Error finding user: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	if checkEmail {
		logrus.Warn("Email already exists")
		return &auth.RegisterResponse{Status: http.StatusConflict, Message: "Email already exists", AccessToken: "", RefreshToken: ""}, nil
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		logrus.Errorf("Error hashing password: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	// covert req.GetDob() to time.Time
	dob, err := time.Parse("2006-01-02", req.GetDob())
	if err != nil {
		logrus.Errorf("Error parsing dob: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	// Create user
	user := &model.UserRegister{
		Username:     req.GetUsername(),
		Email:        req.GetEmail(),
		Password:     string(hashedPassword),
		FistName:     req.GetFirstName(),
		LastName:     req.GetLastName(),
		Dob:          dob,
		PlaceOfBirth: req.GetPlaceOfBirth(),
		PhoneNumber:  req.GetPhoneNumber(),
	}
	res, err := s.repo.CreateUser(user)
	if err != nil {
		logrus.Errorf("Error creating user: %v", err)
		return nil, fmt.Errorf("internal server error")
	}
	lastId, err := res.LastInsertId()
	if err != nil {
		logrus.Errorf("Error getting last insert ID: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	// int64 to int
	userId := int(lastId)
	accessToken, refreshToken, err := utils.CreateToken(userId, s.config.Get("JWT_SECRET"))
	if err != nil {
		logrus.Errorf("Error creating token: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	err = s.repo.UpdateRefreshToken(userId, refreshToken)
	if err != nil {
		logrus.Errorf("Error updating refresh token: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	logrus.Infof("User %s registered successfully", req.GetUsername())

	return &auth.RegisterResponse{Status: http.StatusOK, Message: "Registration successful", AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s *AuthServiceImpl) RefreshToken(ctx context.Context, req *auth.RefreshTokenRequest) (*auth.RefreshTokenResponse, error) {
	logrus.Infof("Refreshing token for user: token: %s", req.GetRefreshToken())

	userId, err := utils.CheckToken(req.GetRefreshToken(), s.config.Get("JWT_SECRET"))
	if err != nil {
		logrus.Errorf("Error checking token: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	if userId == nil {
		logrus.Warn("Invalid token")
		return &auth.RefreshTokenResponse{Status: http.StatusUnauthorized, Message: "Invalid token", AccessToken: "", RefreshToken: ""}, nil
	}

	// Check if refresh token exists
	checkRefreshToken, err := s.repo.CheckRefreshToken(userId.UserID, req.GetRefreshToken())
	if err != nil {
		logrus.Errorf("Error checking refresh token: %v", err)
		return &auth.RefreshTokenResponse{Status: http.StatusUnauthorized, Message: "Refresh Token Not Found", AccessToken: "", RefreshToken: ""}, nil
	}

	if !checkRefreshToken {
		logrus.Warn("Refresh token not found")
		return &auth.RefreshTokenResponse{Status: http.StatusUnauthorized, Message: "Refresh Token Not Found", AccessToken: "", RefreshToken: ""}, nil
	}

	accessToken, _, err := utils.CreateToken(userId.UserID, s.config.Get("JWT_SECRET"))

	if err != nil {
		logrus.Errorf("Error creating token: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	logrus.Infof("Token refreshed successfully")

	return &auth.RefreshTokenResponse{Status: http.StatusOK, Message: "Token refreshed successfully", AccessToken: accessToken, RefreshToken: req.GetRefreshToken()}, nil

}
