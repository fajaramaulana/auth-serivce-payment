package main

import (
	"database/sql"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock" // import this package for SQL mock support
	"github.com/alicebob/miniredis/v2"
	"github.com/fajaramaulana/auth-serivce-payment/internal/config"
	"github.com/fajaramaulana/auth-serivce-payment/internal/repository"
	"github.com/fajaramaulana/auth-serivce-payment/internal/service"
	"github.com/fajaramaulana/auth-serivce-payment/mocks"
	mockGrpc "github.com/fajaramaulana/shared-proto-payment/mocks"
	"github.com/fajaramaulana/shared-proto-payment/proto/auth"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

func TestSetupServer(t *testing.T) {
	// Set up mock config
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")
	mockConfig.On("Get", "NOTIFICATION_TARGET").Return("localhosttarget")

	// Start a miniredis server for Redis testing
	mockRedis, err := miniredis.Run()
	assert.NoError(t, err)
	defer mockRedis.Close()
	mockConfig.On("Get", "REDIS_HOST").Return(mockRedis.Addr())

	// Mock database and listener
	mockDB := new(sql.DB)
	listenerFunc := func() (net.Listener, error) {
		return net.Listen("tcp", ":0")
	}

	// Run SetupServer with the mock configuration
	grpcServer, grpcClient, listener, redisClient, err := SetupServer(mockConfig, mockDB, listenerFunc)
	assert.NoError(t, err)
	assert.NotNil(t, grpcServer)
	assert.NotNil(t, grpcClient)
	assert.NotNil(t, listener)
	assert.NotNil(t, redisClient)

	// Clean up
	grpcServer.Stop()
	listener.Close()
}

func TestSetupServer_ListenerError(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")
	mockConfig.On("Get", "NOTIFICATION_TARGET").Return("localhosttarget")

	mockDB := new(sql.DB) // Substitute with a real mock DB if available

	// Start a miniredis server for Redis testing
	mockRedis, err := miniredis.Run()
	assert.NoError(t, err)
	defer mockRedis.Close()
	mockConfig.On("Get", "REDIS_HOST").Return(mockRedis.Addr())

	// Inject a listener function that returns an error
	listenerFunc := func() (net.Listener, error) {
		return nil, errors.New("failed to create listener")
	}

	grpcServer, grpcClient, listener, redisClient, err := SetupServer(mockConfig, mockDB, listenerFunc)
	assert.Error(t, err, "expected error when listener creation fails")
	assert.Nil(t, grpcServer, "expected grpcServer to be nil on error")
	assert.Nil(t, grpcClient, "expected grpcClient to be nil on error")
	assert.Nil(t, listener, "expected listener to be nil on error")
	assert.Nil(t, redisClient, "expected grpcClient to be nil on error")
}

// TestMainFunction is a test function for the main function flow
func TestMainFunction(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")
	mockConfig.On("Get", "NOTIFICATION_TARGET").Return("localhosttarget")
	mockConfig.On("Get", "ENV").Return("test")
	mockPassHash := new(mocks.MockPasswordHasher)
	mockToken := new(mocks.MockTokenHandler)

	mockDB := new(sql.DB) // Substitute with a real mock DB if available
	authRepo := repository.NewUserRepository(mockDB, mockConfig)
	mockNotifClient := new(mockGrpc.NotificationServiceClient)

	mockRedis, err := miniredis.Run()
	assert.NoError(t, err)
	defer mockRedis.Close()
	mockConfig.On("Get", "REDIS_HOST").Return(mockRedis.Addr())

	// Create a Redis client based on the mock Redis server
	redisClient := redis.NewClient(&redis.Options{
		Addr: mockRedis.Addr(),
	})
	authService := service.NewAuthService(authRepo, mockConfig, mockPassHash, mockToken, mockNotifClient, redisClient)

	// Create the gRPC server and listener
	grpcServer := grpc.NewServer()
	auth.RegisterAuthServiceServer(grpcServer, authService)

	listener, err := net.Listen("tcp", ":50051")
	assert.NoError(t, err, "expected no error from net.Listen")

	// Use a channel to signal when to stop the server
	done := make(chan struct{})
	go func() {
		defer close(done) // Close the channel when done
		err := grpcServer.Serve(listener)
		assert.NoError(t, err, "expected no error from grpcServer.Serve")
	}()

	// Wait for a short period to ensure the server is up and running
	time.Sleep(time.Millisecond * 100)

	// Your test logic goes here, e.g., making a request to the gRPC server
	// ...

	// Clean up resources after test
	grpcServer.Stop() // Stop the server
	<-done            // Wait for the goroutine to finish
	listener.Close()  // Close the listener
}

// Test cases
func TestRun_Success(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")
	mockConfig.On("Get", "NOTIFICATION_TARGET").Return("localhosttarget")

	mockRedis, err := miniredis.Run()
	assert.NoError(t, err)
	defer mockRedis.Close()
	mockConfig.On("Get", "REDIS_HOST").Return(mockRedis.Addr())

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
	mockConfig.On("Get", "NOTIFICATION_TARGET").Return("localhosttarget")

	mockRedis, err := miniredis.Run()
	assert.NoError(t, err)
	defer mockRedis.Close()
	mockConfig.On("Get", "REDIS_HOST").Return(mockRedis.Addr())

	err = run(mockConfig, mockConnectDBFail, mockListenerSuccess)
	assert.Error(t, err, "expected error on database connection failure")
	assert.EqualError(t, err, "failed to connect to database: failed to connect to database")
}

func TestRun_ListenerFailure(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")
	mockConfig.On("Get", "NOTIFICATION_TARGET").Return("localhosttarget")

	mockRedis, err := miniredis.Run()
	assert.NoError(t, err)
	defer mockRedis.Close()
	mockConfig.On("Get", "REDIS_HOST").Return(mockRedis.Addr())

	err = run(mockConfig, mockConnectDBSuccess, mockListenerFail)
	assert.Error(t, err, "expected error on listener creation failure")
	assert.EqualError(t, err, "failed to set up server: failed to create listener")
}

func TestRun_DBclose(t *testing.T) {
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_HOST").Return("localhost")
	mockConfig.On("Get", "NOTIFICATION_TARGET").Return("localhosttarget")

	mockRedis, err := miniredis.Run()
	assert.NoError(t, err)
	defer mockRedis.Close()
	mockConfig.On("Get", "REDIS_HOST").Return(mockRedis.Addr())

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

	mockRedis, err := miniredis.Run()
	assert.NoError(t, err)
	defer mockRedis.Close()
	mockConfig.On("Get", "REDIS_HOST").Return(mockRedis.Addr())

	err = run(mockConfig, mockConnectDBSuccess, mockListenerFailure)
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
