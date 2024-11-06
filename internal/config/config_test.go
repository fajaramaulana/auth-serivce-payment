package config_test

import (
	"os"
	"testing"

	"github.com/fajaramaulana/auth-serivce-payment/internal/config"
	"github.com/fajaramaulana/auth-serivce-payment/mocks"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	// Create a temporary .env file with sample data
	filenames := ".env.test"
	fileContent := "TEST_KEY=sample_value\n"
	if err := os.WriteFile(filenames, []byte(fileContent), 0644); err != nil {
		t.Fatalf("Failed to create test .env file: %v", err)
	}
	defer os.Remove(filenames) // Clean up after the test

	// Initialize configuration and load test .env file
	cfg := config.New(filenames)

	// Test that the environment variable is loaded correctly
	expectedValue := "sample_value"
	actualValue := cfg.Get("TEST_KEY")
	assert.Equal(t, expectedValue, actualValue, "Expected environment variable to match")
}

func TestLoadConfiguration(t *testing.T) {
	// Set a known environment variable
	os.Setenv("ANOTHER_TEST_KEY", "another_value")
	defer os.Unsetenv("ANOTHER_TEST_KEY")

	// Initialize configuration using LoadConfiguration
	cfg := config.LoadConfiguration()

	// Verify that Get retrieves the correct environment variable value
	expectedValue := "another_value"
	actualValue := cfg.Get("ANOTHER_TEST_KEY")
	assert.Equal(t, expectedValue, actualValue, "Expected environment variable to match")
}

func TestConnectDBMysql_Success(t *testing.T) {
	// Mock the config to return valid values
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_USER").Return("test_user")
	mockConfig.On("Get", "DB_PASSWORD").Return("test_password")
	mockConfig.On("Get", "DB_HOST").Return("localhost")
	mockConfig.On("Get", "DB_PORT").Return("3306")
	mockConfig.On("Get", "DB_TYPE").Return("mysql")
	mockConfig.On("Get", "DB_NAME").Return("test_db")

	// Test a successful connection (sql.Open doesn't connect to the DB)
	db, err := config.ConnectDBMysql(mockConfig)

	// Assert that there was no error and db is not nil
	assert.NoError(t, err)
	assert.NotNil(t, db)

	// Close the DB (important for cleanup)
	defer db.Close()

	// Check all mock expectations were met
	mockConfig.AssertExpectations(t)
}

func TestConnectDBMysql_InvalidPort(t *testing.T) {
	// Mock the config to return an invalid port and required fields
	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Get", "DB_USER").Return("test_user")
	mockConfig.On("Get", "DB_PASSWORD").Return("test_password")
	mockConfig.On("Get", "DB_HOST").Return("localhost")
	mockConfig.On("Get", "DB_PORT").Return("invalid_port") // This will trigger the port conversion error
	mockConfig.On("Get", "DB_TYPE").Return("mysql")
	mockConfig.On("Get", "DB_NAME").Return("test_db") // Ensure DB_NAME is mocked as well

	// Call the function
	db, err := config.ConnectDBMysql(mockConfig)

	// Assert error and nil db
	assert.Error(t, err)
	assert.Nil(t, db)

	// Assert specific calls to identify which might be missing
	mockConfig.AssertCalled(t, "Get", "DB_USER")
	mockConfig.AssertCalled(t, "Get", "DB_PASSWORD")
	mockConfig.AssertCalled(t, "Get", "DB_HOST")

	mockConfig.AssertCalled(t, "Get", "DB_PORT")
	mockConfig.AssertCalled(t, "Get", "DB_TYPE")
	mockConfig.AssertCalled(t, "Get", "DB_NAME")

	// Check all mock expectations were met
	mockConfig.AssertExpectations(t)
}
