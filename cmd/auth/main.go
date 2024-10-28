package main

import (
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

func init() {
	// Initialize Logrus logger
	log := logrus.New()
	log.Out = os.Stdout
	log.SetFormatter(&logrus.JSONFormatter{}) // Optional: set JSON formatting for structured logs
}

func main() {
	configuration := config.LoadConfiguration()
	logrus.Infof("Configuration loaded")
	logrus.Info("Value of key 'DB_HOST':", configuration.Get("DB_HOST"))

	db, err := config.ConnectDBMysql(configuration)
	if err != nil {
		logrus.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize repository and service handler
	authRepo := repository.NewUserRepository(db)
	authService := service.NewAuthService(authRepo, configuration)

	// Initialize gRPC server
	grpcServer := grpc.NewServer()
	auth.RegisterAuthServiceServer(grpcServer, authService) // Pass authService directly

	// Register reflection service on gRPC server
	reflection.Register(grpcServer)

	// Set up listener and serve
	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		logrus.Fatalf("Failed to listen on port 50051: %v", err)
	}
	logrus.Infof("gRPC server listening on port 50051")
	if err := grpcServer.Serve(listener); err != nil {
		logrus.Fatalf("Failed to serve gRPC server: %v", err)
	}
}
