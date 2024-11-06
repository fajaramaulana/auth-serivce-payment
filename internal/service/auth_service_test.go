package service_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/fajaramaulana/auth-serivce-payment/internal/model"
	"github.com/fajaramaulana/auth-serivce-payment/internal/repository"
	"github.com/fajaramaulana/auth-serivce-payment/internal/service"
	"github.com/fajaramaulana/auth-serivce-payment/internal/utils"
	"github.com/fajaramaulana/auth-serivce-payment/mocks"
	"github.com/fajaramaulana/shared-proto-payment/proto/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/genproto/googleapis/type/date"
	"google.golang.org/grpc/status"

	mockGrpc "github.com/fajaramaulana/shared-proto-payment/mocks"
)

func TestAuthServiceImpl_LoginUser(t *testing.T) {
	db, dbmock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' occurred when opening a mock database connection", err)
	}
	defer db.Close()

	mockConfig := new(mocks.MockConfig)
	mockPassHash := new(mocks.MockPasswordHasher)
	mockToken := new(mocks.MockTokenHandler)
	mockConfig.On("Get", "JWT_SECRET").Return("secret")
	mockConfig.On("Get", "ENV").Return("test")
	mockRepo := repository.NewUserRepository(db, mockConfig)
	mockNotifClient := new(mockGrpc.NotificationServiceClient)
	service := service.NewAuthService(mockRepo, mockConfig, mockPassHash, mockToken, mockNotifClient)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	expectedUser := &model.GetUserPassword{
		ID:       int(1),
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}

	// Mock the query to fetch the user
	dbmock.ExpectQuery("SELECT id, username, email, password FROM users WHERE username = ?").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password"}).
			AddRow(expectedUser.ID, expectedUser.Username, expectedUser.Email, expectedUser.Password))

	// Mock the update of the refresh token
	dbmock.ExpectExec("UPDATE users SET refresh_token = \\? WHERE id = \\?").
		WithArgs(sqlmock.AnyArg(), expectedUser.ID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mockToken.On("CreateToken", 1).Return("new_valid_access_token", "valid_refresh_token", nil)
	mockNotifClient.On("SendNotification", mock.Anything, mock.Anything).Return(nil, nil)
	req := &auth.LoginRequest{Username: "testuser", Password: "password123"}
	resp, err := service.LoginUser(context.Background(), req)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, int(resp.Status))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)

	// Ensure all expectations were met
	if err := dbmock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

func TestAuthServiceImpl_LoginUser_ErrorCases(t *testing.T) {
	db, dbmock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' occurred when opening a mock database connection", err)
	}
	defer db.Close()

	mockConfig := new(mocks.MockConfig)
	mockPassHash := new(mocks.MockPasswordHasher)
	mockToken := new(mocks.MockTokenHandler)
	mockConfig.On("Get", "JWT_SECRET").Return("secret")
	mockConfig.On("Get", "ENV").Return("test")
	mockRepo := repository.NewUserRepository(db, mockConfig)
	mockNotifClient := new(mockGrpc.NotificationServiceClient)
	service := service.NewAuthService(mockRepo, mockConfig, mockPassHash, mockToken, mockNotifClient)

	username := "testuser1"

	// Mock SQL query to return sql.ErrNoRows to simulate a "user not found" scenario
	dbmock.ExpectQuery("SELECT id, username, email, password FROM users WHERE username = ?").
		WithArgs(username).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password"})) // No rows returned

	reqNotFound := &auth.LoginRequest{Username: "nonexistentuser", Password: "password123"}
	respNotFound, err := service.LoginUser(context.Background(), reqNotFound)
	assert.NoError(t, err)
	assert.NotNil(t, respNotFound)                                       // Check that response is not nil
	assert.Equal(t, int32(http.StatusUnauthorized), respNotFound.Status) // Check the response status
	assert.Equal(t, "Invalid credentials", respNotFound.Message)         // Check the response message
}

func TestAuthServiceImpl_LoginUser_UserNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' occurred when opening a mock database connection", err)
	}
	defer db.Close()

	mockConfig := new(mocks.MockConfig)
	mockPassHash := new(mocks.MockPasswordHasher)
	mockToken := new(mocks.MockTokenHandler)
	mockConfig.On("Get", "JWT_SECRET").Return("secret")
	mockConfig.On("Get", "ENV").Return("test")
	mockRepo := repository.NewUserRepository(db, mockConfig)
	mockNotifClient := new(mockGrpc.NotificationServiceClient)
	service := service.NewAuthService(mockRepo, mockConfig, mockPassHash, mockToken, mockNotifClient)

	// Scenario: User Not Found
	req := &auth.LoginRequest{Username: "nonexistentuser", Password: "password123"}

	// Mock the repository to return no user
	mock.ExpectQuery("SELECT id, username, email, password FROM users WHERE username = ?").
		WithArgs("nonexistentuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password"})) // No rows returned

	// Call the LoginUser method
	resp, err := service.LoginUser(context.Background(), req)

	// Assertions
	assert.NoError(t, err)                                       // No error should be returned
	assert.NotNil(t, resp)                                       // Check that response is not nil
	assert.Equal(t, int32(http.StatusUnauthorized), resp.Status) // Check response status
	assert.Equal(t, "Invalid credentials", resp.Message)         // Check response message
	assert.Empty(t, resp.AccessToken)                            // Ensure access token is empty
	assert.Empty(t, resp.RefreshToken)                           // Ensure refresh token is empty

	// Ensure all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

func TestAuthServiceImpl_LoginUser_PasswordMismatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' occurred when opening a mock database connection", err)
	}
	defer db.Close()

	mockConfig := new(mocks.MockConfig)
	mockPassHash := new(mocks.MockPasswordHasher)
	mockToken := new(mocks.MockTokenHandler)

	mockConfig.On("Get", "JWT_SECRET").Return("secret")
	mockConfig.On("Get", "ENV").Return("test")
	mockRepo := repository.NewUserRepository(db, mockConfig)
	mockNotifClient := new(mockGrpc.NotificationServiceClient)
	service := service.NewAuthService(mockRepo, mockConfig, mockPassHash, mockToken, mockNotifClient)

	// Prepare the hashed password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

	// Scenario: Password Mismatch
	req := &auth.LoginRequest{Username: "testuser", Password: "wrongpassword"}

	// Mock the repository to return a user with the correct hashed password
	mock.ExpectQuery("SELECT id, username, email, password FROM users WHERE username = ?").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password"}).
			AddRow(1, "testuser", "test@example.com", string(hashedPassword))) // Return a user with the hashed password

	// Call the LoginUser method
	resp, err := service.LoginUser(context.Background(), req)

	// Assertions
	assert.NoError(t, err)                                       // No error should be returned
	assert.NotNil(t, resp)                                       // Check that response is not nil
	assert.Equal(t, int32(http.StatusUnauthorized), resp.Status) // Check response status
	assert.Equal(t, "Invalid credentials", resp.Message)         // Check response message
	assert.Empty(t, resp.AccessToken)                            // Ensure access token is empty
	assert.Empty(t, resp.RefreshToken)                           // Ensure refresh token is empty

	// Ensure all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

func TestAuthServiceImpl_LoginUser_TokenCreationError(t *testing.T) {
	db, mockdb, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' occurred when opening a mock database connection", err)
	}
	defer db.Close()

	mockConfig := new(mocks.MockConfig)
	mockPassHash := new(mocks.MockPasswordHasher)
	mockToken := new(mocks.MockTokenHandler)

	mockConfig.On("Get", "JWT_SECRET").Return("secret")
	mockConfig.On("Get", "ENV").Return("test")
	mockRepo := repository.NewUserRepository(db, mockConfig)
	mockNotifClient := new(mockGrpc.NotificationServiceClient)
	service := service.NewAuthService(mockRepo, mockConfig, mockPassHash, mockToken, mockNotifClient)

	// Prepare the hashed password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

	// Scenario: Successful user retrieval
	req := &auth.LoginRequest{Username: "testuser", Password: "password123"}

	// Mock the repository to return a user with the correct hashed password
	mockdb.ExpectQuery("SELECT id, username, email, password FROM users WHERE username = ?").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password"}).
			AddRow(1, "testuser", "test@example.com", string(hashedPassword))) // Return a user with the hashed password

	// Mock the CreateToken function to return an error
	mockToken.On("CreateToken", mock.Anything, mock.Anything).Return("", "", errors.New("token creation error"))

	// Call the LoginUser method
	resp, err := service.LoginUser(context.Background(), req)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(http.StatusInternalServerError), resp.Status)
	assert.Equal(t, "Internal server error", resp.Message)
	assert.Empty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken)

	// Ensure all expectations were met
	if err := mockdb.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

func TestAuthServiceImpl_RegisterUser(t *testing.T) {
	db, dbMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' occurred when opening a mock database connection", err)
	}
	defer db.Close()

	mockConfig := new(mocks.MockConfig)
	mockPassHash := new(mocks.MockPasswordHasher)
	mockToken := new(mocks.MockTokenHandler)

	mockConfig.On("Get", "JWT_SECRET").Return("secret")
	mockConfig.On("Get", "ENV").Return("test")
	mockRepo := repository.NewUserRepository(db, mockConfig)
	mockNotifClient := new(mockGrpc.NotificationServiceClient)
	service := service.NewAuthService(mockRepo, mockConfig, mockPassHash, mockToken, mockNotifClient)

	username := "testuser"
	email := "test@example.com"
	expectedUser := &model.UserRegister{
		Username:     username,
		Email:        email,
		FistName:     "Test",
		LastName:     "User",
		Dob:          utils.TimeMustParse("2006-01-02"),
		PlaceOfBirth: "Jakarta",
		PhoneNumber:  "081111111111",
	}

	mockPassHash.On("Generate", mock.Anything, bcrypt.DefaultCost).Return([]byte("hashedpassword"), nil)

	mockToken.On("CreateToken", 1).Return("new_valid_access_token", "valid_refresh_token", nil)

	// Mock the query to fetch the user
	dbMock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE username = \\?").
		WithArgs(username).
		WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0)) // No existing user

	// Mock the query to fetch the email
	dbMock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE email = \\?").
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0)) // No existing email

	dbMock.ExpectBegin()
	// mock the query to insert user
	dbMock.ExpectExec("INSERT INTO users").
		WithArgs(expectedUser.Username, expectedUser.Email, sqlmock.AnyArg(), expectedUser.FistName, expectedUser.LastName, expectedUser.Dob, expectedUser.PlaceOfBirth, expectedUser.PhoneNumber).
		WillReturnResult(sqlmock.NewResult(1, 1))
	dbMock.ExpectCommit()

	// mock the update of the refresh token
	dbMock.ExpectExec("UPDATE users SET refresh_token = \\? WHERE id = \\?").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	req := &auth.RegisterRequest{
		Username:  username,
		Email:     email,
		Password:  "password123",
		FirstName: "Test",
		LastName:  "User",
		Dob: &date.Date{
			Year:  int32(expectedUser.Dob.Year()),
			Month: int32(expectedUser.Dob.Month()),
			Day:   int32(expectedUser.Dob.Day()),
		},
		PlaceOfBirth: "Jakarta",
		PhoneNumber:  "081111111111",
	}

	resp, err := service.RegisterUser(context.Background(), req)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, int(resp.Status))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)

	// Ensure all expectations were met
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

// TestAuthServiceImpl_RegisterUser_ErrorCases.go
func TestAuthServiceImpl_RegisterUser_ErrorCases(t *testing.T) {
	type errorCase int
	const (
		ErrorUsernameExists errorCase = iota
		ErrorEmailExists
		ErrorQueryUsername
		ErrorQueryEmail
		ErrorFailHashPassword
		ErrorInvalidDob
		ErrorCreateUser
		ErrorGetLastInsertId
	)
	username := "testuser"
	email := "testuser@mail.com"
	dob, _ := time.Parse("2006-01-02", "2006-01-02")
	tests := []struct {
		name         string
		errorType    errorCase
		setupSqlMock func(mock sqlmock.Sqlmock)
		setupUtils   func(mock *mocks.MockTokenHandler, mockHash *mocks.MockPasswordHasher)
		req          *auth.RegisterRequest
	}{
		{
			name:      "Username already exists",
			errorType: ErrorUsernameExists,
			setupSqlMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE username = \\?").
					WithArgs(username).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(1)) // Simulate existing username
			},
			setupUtils: func(mockToken *mocks.MockTokenHandler, mockHash *mocks.MockPasswordHasher) {
				mockHash.On("Generate", mock.Anything, bcrypt.DefaultCost).Return([]byte("hashedpassword"), nil)
				mockToken.On("CreateToken", mock.Anything, mock.Anything).Return("abcd", "abcd", "")
			},
			req: &auth.RegisterRequest{
				Username:  username,
				Email:     email,
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
				Dob: &date.Date{
					Year:  int32(dob.Year()),
					Month: int32(dob.Month()),
					Day:   int32(dob.Day()),
				},
				PlaceOfBirth: "Jakarta",
				PhoneNumber:  "081111111111",
			},
		},
		{
			name:      "Email already exists",
			errorType: ErrorEmailExists,
			setupSqlMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE username = \\?").
					WithArgs(username).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0)) // Simulate existing username

				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE email = \\?").
					WithArgs(email).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(1)) // Simulate existing email
			},
			setupUtils: func(mockToken *mocks.MockTokenHandler, mockHash *mocks.MockPasswordHasher) {
				mockHash.On("Generate", mock.Anything, bcrypt.DefaultCost).Return([]byte("hashedpassword"), nil)
				mockToken.On("CreateToken", mock.Anything, mock.Anything).Return("abcd", "abcd", "")
			},
			req: &auth.RegisterRequest{
				Username:  username,
				Email:     email,
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
				Dob: &date.Date{
					Year:  int32(dob.Year()),
					Month: int32(dob.Month()),
					Day:   int32(dob.Day()),
				},
				PlaceOfBirth: "Jakarta",
				PhoneNumber:  "081111111111",
			},
		},
		{
			name:      "Error Query Username",
			errorType: ErrorQueryUsername,
			setupSqlMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE username = \\?").
					WithArgs(username).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}))
			},
			setupUtils: func(mockToken *mocks.MockTokenHandler, mockHash *mocks.MockPasswordHasher) {
				mockHash.On("Generate", mock.Anything, bcrypt.DefaultCost).Return([]byte("hashedpassword"), nil)
				mockToken.On("CreateToken", mock.Anything, mock.Anything).Return("abcd", "abcd", "")
			},
			req: &auth.RegisterRequest{
				Username:  username,
				Email:     email,
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
				Dob: &date.Date{
					Year:  int32(dob.Year()),
					Month: int32(dob.Month()),
					Day:   int32(dob.Day()),
				},
				PlaceOfBirth: "Jakarta",
				PhoneNumber:  "081111111111",
			},
		},
		{
			name:      "Error Query Email",
			errorType: ErrorQueryEmail,
			setupSqlMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE username = \\?").
					WithArgs(username).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0))
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE email = \\?").
					WithArgs(email).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}))
			},
			setupUtils: func(mockToken *mocks.MockTokenHandler, mockHash *mocks.MockPasswordHasher) {
				mockHash.On("Generate", mock.Anything, bcrypt.DefaultCost).Return([]byte("hashedpassword"), nil)
				mockToken.On("CreateToken", mock.Anything, mock.Anything).Return("abcd", "abcd", "")
			},
			req: &auth.RegisterRequest{
				Username:  username,
				Email:     email,
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
				Dob: &date.Date{
					Year:  int32(dob.Year()),
					Month: int32(dob.Month()),
					Day:   int32(dob.Day()),
				},
				PlaceOfBirth: "Jakarta",
				PhoneNumber:  "081111111111",
			},
		},
		{
			name:      "Fail to hash password",
			errorType: ErrorFailHashPassword,
			setupSqlMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE username = \\?").
					WithArgs(username).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0))
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE email = \\?").
					WithArgs(email).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0))
			},
			setupUtils: func(mockToken *mocks.MockTokenHandler, mockHash *mocks.MockPasswordHasher) {
				// Simulate hashing error
				mockHash.On("Generate", mock.Anything, bcrypt.DefaultCost).Return(nil, fmt.Errorf("hashing error"))
				mockToken.On("CreateToken", mock.Anything, mock.Anything).Return("", "", fmt.Errorf("token creation error"))
			},
			req: &auth.RegisterRequest{
				Username:  username,
				Email:     email,
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
				Dob: &date.Date{
					Year:  int32(dob.Year()),
					Month: int32(dob.Month()),
					Day:   int32(dob.Day()),
				},
				PlaceOfBirth: "Jakarta",
				PhoneNumber:  "081111111111",
			},
		},
		{
			name:      "Fail invalid date",
			errorType: ErrorFailHashPassword,
			setupSqlMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE username = \\?").
					WithArgs(username).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0))
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE email = \\?").
					WithArgs(email).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0))
			},
			setupUtils: func(mockToken *mocks.MockTokenHandler, mockHash *mocks.MockPasswordHasher) {
				// Simulate hashing error
				mockHash.On("Generate", mock.Anything, bcrypt.DefaultCost).Return([]byte("hashedpassword"), nil)
			},
			req: &auth.RegisterRequest{
				Username:  username,
				Email:     email,
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
				Dob: &date.Date{
					Year:  0,
					Month: 0,
					Day:   0,
				},
				PlaceOfBirth: "Jakarta",
				PhoneNumber:  "081111111111",
			},
		},
		{
			name:      "Fail to Create User",
			errorType: ErrorCreateUser,
			setupSqlMock: func(mock sqlmock.Sqlmock) {
				// Setup mock for username and email checks
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE username = \\?").
					WithArgs(username).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0))
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE email = \\?").
					WithArgs(email).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0))

				// Expect transaction Begin before insert execution
				mock.ExpectBegin()

				dob, _ := time.Parse("2006-01-02", "2006-01-02")

				// Simulate failure on user insertion
				mock.ExpectExec("INSERT INTO users").
					WithArgs(username, email, sqlmock.AnyArg(), "Test", "User", dob, "Jakarta", "081111111111").
					WillReturnError(errors.New("database error"))

				// Expect rollback due to insert failure
				mock.ExpectRollback()
			},
			setupUtils: func(mockToken *mocks.MockTokenHandler, mockHash *mocks.MockPasswordHasher) {
				mockHash.On("Generate", mock.Anything, bcrypt.DefaultCost).Return([]byte("hashedpassword"), nil)
			},
			req: &auth.RegisterRequest{
				Username:  username,
				Email:     email,
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
				Dob: &date.Date{
					Year:  int32(dob.Year()),
					Month: int32(dob.Month()),
					Day:   int32(dob.Day()),
				},
				PlaceOfBirth: "Jakarta",
				PhoneNumber:  "081111111111",
			},
		},
		{
			name:      "Fail to Get Last Id",
			errorType: ErrorGetLastInsertId,
			setupSqlMock: func(mock sqlmock.Sqlmock) {
				// Mock for checking existing username
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE username = \\?").
					WithArgs(username).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0))

				// Mock for checking existing email
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE email = \\?").
					WithArgs(email).
					WillReturnRows(sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(0))

				// Expect transaction begin
				mock.ExpectBegin()

				// Mock for the insert user operation, returning result with LastInsertId
				mock.ExpectExec("INSERT INTO users").
					WithArgs(username, email, sqlmock.AnyArg(), "Test", "User", dob, "Jakarta", "081111111111").
					WillReturnResult(sqlmock.NewResult(1, 1)) // Simulate successful insert

				// Expect commit
				mock.ExpectCommit()
			},
			setupUtils: func(mockToken *mocks.MockTokenHandler, mockHash *mocks.MockPasswordHasher) {
				mockHash.On("Generate", mock.Anything, bcrypt.DefaultCost).Return([]byte("hashedpassword"), nil)
				mockToken.On("CreateToken", 1).Return("new_valid_access_token", "valid_refresh_token", nil)
			},
			req: &auth.RegisterRequest{
				Username:  username,
				Email:     email,
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
				Dob: &date.Date{
					Year:  int32(dob.Year()),
					Month: int32(dob.Month()),
					Day:   int32(dob.Day()),
				},
				PlaceOfBirth: "Jakarta",
				PhoneNumber:  "081111111111",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mockDb, err := sqlmock.New()
			if err != nil {
				t.Fatalf("an error '%s' occurred when opening a mock database connection", err)
			}
			defer db.Close()

			mockConfig := new(mocks.MockConfig)
			mockPassHash := new(mocks.MockPasswordHasher)
			mockToken := new(mocks.MockTokenHandler)

			mockConfig.On("Get", "JWT_SECRET").Return("secret")
			mockConfig.On("Get", "ENV").Return("test")
			mockRepo := repository.NewUserRepository(db, mockConfig)

			mockNotifClient := new(mockGrpc.NotificationServiceClient)
			service := service.NewAuthService(mockRepo, mockConfig, mockPassHash, mockToken, mockNotifClient)

			tt.setupSqlMock(mockDb)

			req := tt.req

			tt.setupUtils(mockToken, mockPassHash)

			resp, err := service.RegisterUser(context.Background(), req)

			// Switch to check specific assertions based on the error case
			switch tt.errorType {
			case ErrorUsernameExists:
				assert.NoError(t, err)
				assert.Equal(t, http.StatusConflict, int(resp.Status))
				assert.Equal(t, "Username already exists", resp.Message)
				assert.Empty(t, resp.AccessToken)
				assert.Empty(t, resp.RefreshToken)

			case ErrorEmailExists:
				assert.NoError(t, err)
				assert.Equal(t, http.StatusConflict, int(resp.Status))
				assert.Equal(t, "Email already exists", resp.Message)
				assert.Empty(t, resp.AccessToken)
				assert.Empty(t, resp.RefreshToken)

			case ErrorQueryUsername:
				assert.Error(t, err)
			case ErrorQueryEmail:
				assert.Error(t, err)
			case ErrorFailHashPassword:
				assert.Error(t, err)
				assert.Nil(t, resp)
			case ErrorInvalidDob:
				assert.Error(t, err)
				assert.Nil(t, resp)
				assert.Contains(t, err.Error(), "internal server error")
			case ErrorCreateUser:
				assert.Error(t, err)
				assert.Nil(t, resp)
				assert.Contains(t, err.Error(), "internal server error")
			case ErrorGetLastInsertId:
				assert.Error(t, err)
				assert.Nil(t, resp)
			}

			// Ensure all expectations were met
			if err := mockDb.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled mock expectations: %v", err)
			}
		})
	}
}

func TestAuthServiceImpl_RefreshToken(t *testing.T) {
	jwtSecret := "your_jwt_secret"
	userId := 123
	refreshToken := "valid_refresh_token"

	tests := []struct {
		name               string
		req                *auth.RefreshTokenRequest
		mockCheckToken     func(mock *mocks.MockTokenHandler)
		mockCheckTokenRepo func(mock *mocks.MockRepository)
		expectResponse     *auth.RefreshTokenResponse
		expectError        bool
	}{
		{
			name: "Successful token refresh",
			req: &auth.RefreshTokenRequest{
				RefreshToken: refreshToken,
			},
			mockCheckToken: func(mock *mocks.MockTokenHandler) {
				mock.On("CheckToken", refreshToken).Return(&utils.CustomClaims{UserID: userId}, nil)
				mock.On("CreateToken", userId).Return("new_valid_access_token", refreshToken, nil)
			},
			mockCheckTokenRepo: func(mock *mocks.MockRepository) {
				mock.On("CheckRefreshToken", userId, refreshToken).Return(true, nil)
			},
			expectResponse: &auth.RefreshTokenResponse{
				Status:       http.StatusOK,
				Message:      "Token refreshed successfully",
				AccessToken:  "new_valid_access_token",
				RefreshToken: refreshToken,
			},
			expectError: false,
		},
		// Add more test cases for different scenarios as needed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTokenHandler := new(mocks.MockTokenHandler)
			tt.mockCheckToken(mockTokenHandler)

			mockRepository := new(mocks.MockRepository)
			tt.mockCheckTokenRepo(mockRepository)

			mockConfig := new(mocks.MockConfig)
			mockConfig.On("Get", "JWT_SECRET").Return(jwtSecret)

			// Instantiate AuthServiceImpl with mocked dependencies
			mockNotifClient := new(mockGrpc.NotificationServiceClient)
			authService := service.NewAuthService(mockRepository, mockConfig, nil, mockTokenHandler, mockNotifClient)

			// Call RefreshToken and validate response
			res, err := authService.RefreshToken(context.Background(), tt.req)

			if tt.expectError {
				assert.Error(t, err)
				st, _ := status.FromError(err)
				assert.Equal(t, "internal server error", st.Message())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectResponse, res)
			}

			// Verify all expectations were met
			mockTokenHandler.AssertExpectations(t)
			mockRepository.AssertExpectations(t)
		})
	}
}
