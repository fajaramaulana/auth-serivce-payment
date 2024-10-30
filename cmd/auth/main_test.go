package main

import (
	"database/sql"
	"errors"
	"net"
	"testing"

	"github.com/DATA-DOG/go-sqlmock" // import this package for SQL mock support
	"github.com/fajaramaulana/auth-serivce-payment/internal/config"
	"github.com/fajaramaulana/auth-serivce-payment/internal/repository"
	"github.com/fajaramaulana/auth-serivce-payment/internal/service"
	"github.com/fajaramaulana/auth-serivce-payment/mocks"
	"github.com/fajaramaulana/shared-proto-payment/proto/auth"
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
	mockPassHash := new(mocks.MockPasswordHasher)

	mockToken := new(mocks.MockTokenHandler)

	mockDB := new(sql.DB) // Substitute with a real mock DB if available

	// Mock repository and service
	authRepo := repository.NewUserRepository(mockDB)
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

	err := run(mockConfig, mockConnectDBSuccess, mockListenerSuccess)
	assert.NoError(t, err, "expected no error on successful setup")
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
	assert.EqualError(t, err, "failed to create listener: failed to create listener")
}

func TestRun_DBclose(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")

	err := run(mockConfig, mockConnectDBSuccess, mockListenerSuccess)
	assert.NoError(t, err, "expected no error on successful setup")
}

func TestRun_ListenerCreationFailure(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", mock.Anything).Return("localhost")

	err := run(mockConfig, mockConnectDBSuccess, mockListenerFailure)
	assert.Error(t, err, "expected error on listener creation failure")
	assert.Contains(t, err.Error(), "failed to create listener")
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

func mockListenerFail() (net.Listener, error) {
	return nil, errors.New("failed to create listener")
}

// Mock function for a failed listener creation
func mockListenerFailure() (net.Listener, error) {
	return nil, errors.New("mock listener creation error")
}
