package main

import (
	"database/sql"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock" // import this package for SQL mock support
	"github.com/fajaramaulana/auth-serivce-payment/internal/config"
	"github.com/fajaramaulana/auth-serivce-payment/internal/repository"
	"github.com/fajaramaulana/auth-serivce-payment/internal/service"
	"github.com/fajaramaulana/auth-serivce-payment/mocks"
	"github.com/fajaramaulana/shared-proto-payment/proto/auth"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

func TestSetupServer(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")
	mockDB := new(sql.DB) // Create a new mock DB (or use a real connection if necessary)

	listenerFunc := func() (net.Listener, error) {
		return net.Listen("tcp", ":50051")
	}
	// Test SetupServer
	grpcServer, listener, err := SetupServer(mockConfig, mockDB, listenerFunc)
	assert.NoError(t, err, "expected no error from SetupServer")
	assert.NotNil(t, grpcServer, "expected grpcServer to be initialized")
	assert.NotNil(t, listener, "expected listener to be initialized")

	// Close the server and listener at the end of the test
	grpcServer.Stop()
	listener.Close()
}

func TestSetupServer_ListenerError(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")

	mockDB := new(sql.DB) // Substitute with a real mock DB if available

	// Inject a listener function that returns an error
	listenerFunc := func() (net.Listener, error) {
		return nil, errors.New("failed to create listener")
	}

	grpcServer, listener, err := SetupServer(mockConfig, mockDB, listenerFunc)
	assert.Error(t, err, "expected error when listener creation fails")
	assert.Nil(t, grpcServer, "expected grpcServer to be nil on error")
	assert.Nil(t, listener, "expected listener to be nil on error")
}

// TestMainFunction is a test function for the main function flow
func TestMainFunction(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")
	mockConfig.On("Get", "ENV").Return("test")
	mockPassHash := new(mocks.MockPasswordHasher)

	mockToken := new(mocks.MockTokenHandler)

	mockDB := new(sql.DB) // Substitute with a real mock DB if available

	// Mock repository and service
	authRepo := repository.NewUserRepository(mockDB, mockConfig)
	authService := service.NewAuthService(authRepo, mockConfig, mockPassHash, mockToken)

	// Create the gRPC server and listener
	grpcServer := grpc.NewServer()
	auth.RegisterAuthServiceServer(grpcServer, authService)

	listener, err := net.Listen("tcp", ":50051")
	assert.NoError(t, err, "expected no error from net.Listen")

	go func() {
		err := grpcServer.Serve(listener)
		assert.NoError(t, err, "expected no error from grpcServer.Serve")
	}()

	// Close the server and listener after test
	defer grpcServer.Stop()
	defer listener.Close()
}

// Test cases
func TestRun_Success(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")

	// Run `run` function in a goroutine
	done := make(chan error)
	go func() {
		err := run(mockConfig, mockConnectDBSuccess, mockListenerSuccess2)
		done <- err
	}()

	// Wait for a short delay to ensure the server starts
	time.Sleep(100 * time.Millisecond)

	// Close the server after checking it has started
	select {
	case err := <-done:
		assert.NoError(t, err, "expected no error on successful setup")
	default:
		logrus.Info("Stopping gRPC server after test verification")
		close(done) // Optional: Clean up the done channel
	}
}

func TestRun_DBConnectionFailure(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")

	err := run(mockConfig, mockConnectDBFail, mockListenerSuccess)
	assert.Error(t, err, "expected error on database connection failure")
	assert.EqualError(t, err, "failed to connect to database: failed to connect to database")
}

func TestRun_ListenerFailure(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")

	err := run(mockConfig, mockConnectDBSuccess, mockListenerFail)
	assert.Error(t, err, "expected error on listener creation failure")
	assert.EqualError(t, err, "failed to set up server: failed to create listener")
}

func TestRun_DBclose(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")

	done := make(chan error)
	go func() {
		err := run(mockConfig, mockConnectDBSuccess, mockListenerSuccess2)
		done <- err
	}()

	// Wait for a short delay to ensure the server starts
	time.Sleep(100 * time.Millisecond)

	// Close the server after checking it has started
	select {
	case err := <-done:
		assert.NoError(t, err, "expected no error on successful setup")
	default:
		logrus.Info("Stopping DB after test verification")
		close(done) // Optional: Clean up the done channel
	}
}

func TestRun_ListenerCreationFailure(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", mock.Anything).Return("localhost")

	err := run(mockConfig, mockConnectDBSuccess, mockListenerFailure)
	assert.Error(t, err, "expected error on listener creation failure")
	assert.Contains(t, err.Error(), "failed to set up server")
}

// Mock functions for database connection and listener
func mockConnectDBSuccess(config config.Config) (*sql.DB, error) {
	// Create a mock DB connection
	db, _, _ := sqlmock.New()
	return db, nil
}

func mockConnectDBFail(config config.Config) (*sql.DB, error) {
	return nil, errors.New("failed to connect to database")
}

func mockListenerSuccess() (net.Listener, error) {
	return &net.TCPListener{}, nil
}

// Mock listener function
func mockListenerSuccess2() (net.Listener, error) {
	// Use net.Listen to create a listener on a random port for testing
	return net.Listen("tcp", "127.0.0.1:0")
}

func mockListenerFail() (net.Listener, error) {
	return nil, errors.New("failed to create listener")
}

// Mock function for a failed listener creation
func mockListenerFailure() (net.Listener, error) {
	return nil, errors.New("mock listener creation error")
}
