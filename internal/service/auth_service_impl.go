package service

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/fajaramaulana/auth-serivce-payment/internal/config"
	"github.com/fajaramaulana/auth-serivce-payment/internal/model"
	"github.com/fajaramaulana/auth-serivce-payment/internal/repository"
	"github.com/fajaramaulana/auth-serivce-payment/internal/utils"
	"github.com/fajaramaulana/shared-proto-payment/proto/auth"
	pb "github.com/fajaramaulana/shared-proto-payment/proto/notification"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthServiceImpl struct {
	repo                                repository.UserRepository
	config                              config.Config
	hasher                              utils.PasswordHasher
	token                               utils.TokenHandlerIntf
	notificationClient                  pb.NotificationServiceClient
	rateLimiter                         *RateLimiter
	auth.UnimplementedAuthServiceServer // embed by value
}

func NewAuthService(authRepo repository.UserRepository, config config.Config, hasher utils.PasswordHasher, token utils.TokenHandlerIntf, notificationClient pb.NotificationServiceClient, rateLimiter *RateLimiter) auth.AuthServiceServer {
	return &AuthServiceImpl{
		repo:               authRepo,
		config:             config,
		hasher:             hasher,
		token:              token,
		notificationClient: notificationClient,
		rateLimiter:        rateLimiter,
	}
}

func (s *AuthServiceImpl) LoginUser(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	logrus.Infof("Login attempt for user: %s", req.GetUsername())
	// Find user by username
	// limit :=
	limitRatelimiter := s.config.Get("LIMIT_RATELIMITER")
	limit, err := strconv.Atoi(limitRatelimiter)
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error getting limit ratelimiter: %v", err)
		return &auth.LoginResponse{Status: http.StatusInternalServerError, Message: "Internal server error", AccessToken: "", RefreshToken: ""}, status.Error(codes.Internal, "internal server error")
	}

	periodRateLimiter := s.config.Get("PERIOD_RATELIMITER")
	// convert to time.Duration
	period, err := time.ParseDuration(periodRateLimiter)
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error getting period ratelimiter: %v", err)
		return &auth.LoginResponse{Status: http.StatusInternalServerError, Message: "Internal server error", AccessToken: "", RefreshToken: ""}, status.Error(codes.Internal, "internal server error")
	}

	isAllowed, err := s.rateLimiter.IsAllowed(ctx, req.GetUsername(), limit, period)
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error checking rate limit: %v", err)
		return &auth.LoginResponse{Status: http.StatusInternalServerError, Message: "Internal server error", AccessToken: "", RefreshToken: ""}, status.Error(codes.Internal, "internal server error")
	}

	if !isAllowed {
		logrus.Warn("Rate limit exceeded")
		return &auth.LoginResponse{Status: http.StatusTooManyRequests, Message: "Rate limit exceeded", AccessToken: "", RefreshToken: ""}, status.Error(codes.ResourceExhausted, "rate limit exceeded")
	}

	user, err := s.repo.FindUserByUsername(req.GetUsername())
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error finding user: %v", err)
		return &auth.LoginResponse{Status: http.StatusUnauthorized, Message: "Error when find user", AccessToken: "", RefreshToken: ""}, status.Error(codes.Internal, "internal server error")
	}

	if user == nil {
		logrus.Warn("User not found")
		return &auth.LoginResponse{Status: http.StatusUnauthorized, Message: "Username not found", AccessToken: "", RefreshToken: ""}, status.Error(codes.Unauthenticated, "Username not found")
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.GetPassword())); err != nil {
		logrus.Warn("Password mismatch")
		return &auth.LoginResponse{Status: http.StatusUnauthorized, Message: "Invalid Password", AccessToken: "", RefreshToken: ""}, status.Error(codes.Unauthenticated, "Invalid Password")
	}

	accessToken, refreshToken, err := s.token.CreateToken(user.ID)
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error creating token: %v", err)
		return &auth.LoginResponse{Status: http.StatusInternalServerError, Message: "Internal server error", AccessToken: "", RefreshToken: ""}, status.Error(codes.Internal, "internal server error")
	}

	err = s.repo.UpdateRefreshToken(user.ID, refreshToken)
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error updating refresh token: %v", err)
		return &auth.LoginResponse{Status: http.StatusInternalServerError, Message: "Internal server error", AccessToken: "", RefreshToken: ""}, status.Error(codes.Internal, "internal server error")
	}

	// Example notification sending code
	res, err := s.notificationClient.SendNotification(ctx, &pb.NotificationRequest{
		UserId:    fmt.Sprintf("%d", user.ID),
		Message:   "Login successful",
		Title:     "Someone logged in on your account",
		Type:      "alert",
		IpAddress: req.GetIpAddress(),
		UserAgent: req.UserAgent,
		Timestamp: utils.ConvertToDateTime(time.Now()),
		TypeId:    "1",
	})

	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error sending notification: %v", err)
		return &auth.LoginResponse{Status: http.StatusInternalServerError, Message: "Internal server error", AccessToken: "", RefreshToken: ""}, status.Errorf(codes.Internal, "internal server error")
	}

	if res.GetMessage() != "Success" {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error sending notification: %v", res.GetMessage())
		return &auth.LoginResponse{Status: http.StatusInternalServerError, Message: "Internal server error", AccessToken: "", RefreshToken: ""}, status.Errorf(codes.Internal, "internal server error")
	}

	logrus.Infof("Notification sent: %s", res.GetMessage())
	logrus.Infof("User %s logged in successfully", req.GetUsername())

	return &auth.LoginResponse{Status: http.StatusOK, Message: "Login successful", AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s *AuthServiceImpl) RegisterUser(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	logrus.Infof("Registering user: %s", req.GetUsername())
	// Check if user already exists
	checkUsername, err := s.repo.CheckUserByUsernameRegister(req.GetUsername())
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error finding user: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	if checkUsername {
		logrus.Warn("Username already exists")
		return &auth.RegisterResponse{Status: http.StatusConflict, Message: "Username already exists", AccessToken: "", RefreshToken: ""}, status.Errorf(codes.AlreadyExists, "username already exists")
	}

	checkEmail, err := s.repo.CheckUserByEmailRegister(req.GetEmail())
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error finding email: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	if checkEmail {
		logrus.Warn("Email already exists")
		return &auth.RegisterResponse{Status: http.StatusConflict, Message: "Email already exists", AccessToken: "", RefreshToken: ""}, status.Error(codes.AlreadyExists, "email already exists")
	}

	hashedPassword, err := s.hasher.Generate([]byte(req.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error hashing password: %v", err)
		return nil, fmt.Errorf("internal server error %v", err)
	}

	// covert req.GetDob() to time.Time
	dobStr := fmt.Sprintf("%d-%02d-%02d", req.GetDob().GetYear(), req.GetDob().GetMonth(), req.GetDob().GetDay())
	dob, err := time.Parse("2006-01-02", dobStr)
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error parsing dob: %v", err)
		return nil, fmt.Errorf("internal server error %v", err)
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
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error creating user: %v", err)
		return nil, fmt.Errorf("internal server error")
	}
	lastId, err := res.LastInsertId()
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error getting last insert ID: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	// int64 to int
	userId := int(lastId)
	accessToken, refreshToken, err := s.token.CreateToken(userId)
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error creating token: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	err = s.repo.UpdateRefreshToken(userId, refreshToken)
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error updating refresh token: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	resNotif, err := s.notificationClient.SendNotification(ctx, &pb.NotificationRequest{
		UserId:    fmt.Sprintf("%d", userId),
		Message:   "Registration successful",
		Title:     "Welcome to the platform",
		Type:      "alert",
		IpAddress: req.GetIpAddress(),
		UserAgent: req.GetUserAgent(),
		Timestamp: utils.ConvertToDateTime(time.Now()),
		TypeId:    "2",
	})

	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error sending notification: %v", err)
		return &auth.RegisterResponse{Status: http.StatusInternalServerError, Message: "Internal server error", AccessToken: "", RefreshToken: ""}, status.Errorf(codes.Internal, "internal server error")
	}

	if resNotif.GetMessage() != "Success" {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error sending notification: %v", resNotif.GetMessage())
		return &auth.RegisterResponse{Status: http.StatusInternalServerError, Message: "Internal server error", AccessToken: "", RefreshToken: ""}, status.Errorf(codes.Internal, "internal server error")
	}

	logrus.WithFields(logrus.Fields{"request": req}).Infof("User %s registered successfully", req.GetUsername())

	return &auth.RegisterResponse{Status: http.StatusOK, Message: "Registration successful", AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s *AuthServiceImpl) RefreshToken(ctx context.Context, req *auth.RefreshTokenRequest) (*auth.RefreshTokenResponse, error) {
	logrus.Infof("Refreshing token for user: token: %s", req.GetRefreshToken())

	userIdResult, err := s.token.CheckToken(req.GetRefreshToken())
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error checking token: %v", err)
		return nil, status.Errorf(codes.Internal, "internal server error")
	}

	// Add a call to `CheckRefreshToken` here if needed.
	isTokenValid, err := s.repo.CheckRefreshToken(userIdResult.UserID, req.GetRefreshToken())
	if err != nil || !isTokenValid {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error validating refresh token: %v", err)
		return nil, status.Errorf(codes.Internal, "refresh token invalid or expired")
	}

	newAccessToken, _, err := s.token.CreateToken(userIdResult.UserID)
	if err != nil {
		logrus.WithFields(logrus.Fields{"request": req}).Errorf("Error creating new access token: %v", err)
		return nil, status.Errorf(codes.Internal, "internal server error")
	}

	return &auth.RefreshTokenResponse{
		Status:       http.StatusOK,
		Message:      "Token refreshed successfully",
		AccessToken:  newAccessToken,
		RefreshToken: req.GetRefreshToken(),
	}, nil
}
