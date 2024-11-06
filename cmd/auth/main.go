package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/fajaramaulana/auth-serivce-payment/internal/config"
	"github.com/fajaramaulana/auth-serivce-payment/internal/repository"
	"github.com/fajaramaulana/auth-serivce-payment/internal/service"
	"github.com/fajaramaulana/auth-serivce-payment/internal/utils"
	"github.com/fajaramaulana/shared-proto-payment/proto/auth"
	pb "github.com/fajaramaulana/shared-proto-payment/proto/notification"
	"github.com/go-redis/redis/v8"
	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var ListenerFunc = func() (net.Listener, error) {
	return net.Listen("tcp", ":50051")
}

func init() {
	// Create the logs directory if it doesn't exist
	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		os.Mkdir("logs", 0755)
	}

	// Set up Lumberjack logger for log rotation with JSON format
	fileLogger := &lumberjack.Logger{
		Filename:   "logs/auth-service-payment.log",
		MaxSize:    10,   // Maximum size in megabytes before rotating
		MaxBackups: 3,    // Maximum number of old log files to keep
		MaxAge:     28,   // Maximum number of days to retain a log file
		Compress:   true, // Compress old log files
	}

	// Create a MultiWriter to write to both stdout and file
	multiWriter := io.MultiWriter(os.Stdout, fileLogger)

	// Configure the global logrus logger to write to both outputs
	logrus.SetOutput(multiWriter)
	logrus.SetLevel(logrus.InfoLevel)

	// Set JSON format for log files and plain text for terminal
	logrus.SetFormatter(&logrus.JSONFormatter{})
}

func SetupServer(configuration config.Config, db *sql.DB, ListenerFunc func() (net.Listener, error)) (*grpc.Server, *grpc.ClientConn, net.Listener, *redis.Client, error) {
	// Initialize repository and service handler
	authRepo := repository.NewUserRepository(db, configuration)
	passwordHasher := utils.NewPasswordHasher()
	tokenHandler := utils.NewTokenHandler(configuration)

	notificationTarget := configuration.Get("NOTIFICATION_TARGET")

	// Setup for Notification Service client
	// Setup for Notification Service client
	notificationConn, err := grpc.NewClient(notificationTarget, grpc.WithInsecure(), grpc.WithBlock(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{}
			logrus.Infof("Dialing to %s", addr)
			return d.DialContext(ctx, "tcp", addr)
		}))

	if err != nil {
		// Handle connection error
		return nil, nil, nil, nil, err
	}

	redisClient, err := SetupRedisRetry(configuration)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create NotificationServiceClient
	notificationClient := pb.NewNotificationServiceClient(notificationConn)
	authService := service.NewAuthService(authRepo, configuration, passwordHasher, tokenHandler, notificationClient, redisClient)

	// Initialize gRPC server
	grpcServer := grpc.NewServer()
	auth.RegisterAuthServiceServer(grpcServer, authService) // Pass authService directly

	// Register reflection service on gRPC server
	reflection.Register(grpcServer)

	// Set up listener
	listener, err := ListenerFunc()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return grpcServer, notificationConn, listener, redisClient, nil
}

func main() {
	configuration := config.LoadConfiguration()
	logrus.Infof("Configuration loaded")
	if err := run(configuration, config.ConnectDBMysql, ListenerFunc); err != nil {
		logrus.Fatalf("Application failed: %v", err)
	}
}

func run(config config.Config, connectDB func(config.Config) (*sql.DB, error), createListener func() (net.Listener, error)) error {
	// Attempt to connect to the database
	db, err := connectDB(config)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		if db != nil {
			db.Close()
		}
	}()

	// Set up the gRPC server and listener
	grpcServer, grpcClient, listener, redisClient, err := SetupServer(config, db, createListener)
	if err != nil {
		return fmt.Errorf("failed to set up server: %w", err)
	}
	defer listener.Close()

	defer func() {
		if err := grpcClient.Close(); err != nil {
			logrus.Errorf("Failed to close notification connection: %v", err)
		}
	}()

	defer func() {
		if err := redisClient.Close(); err != nil {
			logrus.Errorf("Failed to close Redis connection: %v", err)
		}
	}()

	// Start serving the gRPC server
	logrus.Info("Starting gRPC server...")
	logrus.Infof("gRPC server started successfully on port: %s", listener.Addr().String())
	if err := grpcServer.Serve(listener); err != nil {
		return fmt.Errorf("failed to serve gRPC server: %w", err)
	}

	return nil
}

func SetupRedisRetry(config config.Config) (*redis.Client, error) {
	var redisClient *redis.Client
	operation := func() error {
		// Initialize Redis client
		redisClient = redis.NewClient(&redis.Options{
			Addr: config.Get("REDIS_HOST"),
			DB:   0,
		})

		// Attempt to ping Redis to verify the connection
		_, err := redisClient.Ping(context.Background()).Result()
		if err != nil {
			logrus.Warnf("Failed to connect to Redis: %v", err)
			return err // Return error to trigger a retry
		}

		logrus.Info("Connected to Redis successfully")
		return nil // Success
	}

	// Define exponential backoff with the `backoff` package
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxElapsedTime = 30 * time.Second // Customize max elapsed time

	// Retry operation with backoff
	err := backoff.Retry(operation, expBackoff)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis after retries: %w", err)
	}

	return redisClient, nil
}
