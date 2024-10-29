package main

import (
	"database/sql"
	"fmt"
	"net"
	"os"

	"github.com/fajaramaulana/auth-serivce-payment/internal/config"
	"github.com/fajaramaulana/auth-serivce-payment/internal/repository"
	"github.com/fajaramaulana/auth-serivce-payment/internal/service"
	"github.com/fajaramaulana/shared-proto-payment/proto/auth"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var ListenerFunc = func() (net.Listener, error) {
	return net.Listen("tcp", ":50051")
}

func init() {
	// Initialize Logrus logger
	log := logrus.New()
	log.Out = os.Stdout
	log.SetFormatter(&logrus.JSONFormatter{}) // Optional: set JSON formatting for structured logs
}

func SetupServer(configuration config.Config, db *sql.DB, ListenerFunc func() (net.Listener, error)) (*grpc.Server, net.Listener, error) {
	// Initialize repository and service handler
	authRepo := repository.NewUserRepository(db)
	authService := service.NewAuthService(authRepo, configuration)

	// Initialize gRPC server
	grpcServer := grpc.NewServer()
	auth.RegisterAuthServiceServer(grpcServer, authService) // Pass authService directly

	// Register reflection service on gRPC server
	reflection.Register(grpcServer)

	// Set up listener
	listener, err := ListenerFunc()
	if err != nil {
		return nil, nil, err
	}

	return grpcServer, listener, nil
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

	// Ensure db is closed only if it’s initialized
	defer func() {
		if db != nil {
			db.Close()
		}
	}()

	// Attempt to create the listener
	listener, err := createListener()
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	defer listener.Close()

	// Continue with the rest of the function logic...
	return nil
}
