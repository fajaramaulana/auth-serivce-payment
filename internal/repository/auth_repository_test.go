package repository_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/fajaramaulana/auth-serivce-payment/internal/model"
	"github.com/fajaramaulana/auth-serivce-payment/internal/repository"
	"github.com/stretchr/testify/assert"
)

func TestFindUserByUsername(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "testuser"
	expectedUser := &model.GetUserPassword{
		ID:       1,
		Username: username,
		Email:    "test@example.com",
		Password: "hashedpassword",
	}

	// Mock SQL query and expected result
	rows := sqlmock.NewRows([]string{"id", "username", "email", "password"}).
		AddRow(expectedUser.ID, expectedUser.Username, expectedUser.Email, expectedUser.Password)
	mock.ExpectQuery("SELECT id, username, email, password FROM users WHERE username = ?").
		WithArgs(username).
		WillReturnRows(rows)

	// Test the function
	user, err := repo.FindUserByUsername(username)
	assert.NoError(t, err)
	assert.Equal(t, expectedUser, user)
}

func TestFindUserByUsername_notfound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	// Username that does not exist in the database
	username := "testuser1"

	// Mock SQL query to return sql.ErrNoRows to simulate a "user not found" scenario
	mock.ExpectQuery("SELECT id, username, email, password FROM users WHERE username = ?").
		WithArgs(username).
		WillReturnError(sql.ErrNoRows)

	// Test the function
	user, err := repo.FindUserByUsername(username)

	// Expecting an error for "user not found"
	assert.NoError(t, err) // No error expected since "user not found" should return nil
	assert.Nil(t, user)    // The user should be nil since it does not exist
}

func TestFindUserByEmail(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	email := "test@example.com"
	expectedUser := &model.GetUserPassword{
		ID:       1,
		Username: "testuser",
		Email:    email,
		Password: "hashedpassword",
	}

	// Mock SQL query and expected result
	rows := sqlmock.NewRows([]string{"id", "username", "email", "password"}).
		AddRow(expectedUser.ID, expectedUser.Username, expectedUser.Email, expectedUser.Password)
	mock.ExpectQuery("SELECT id, username, email, password FROM users WHERE email = ?").
		WithArgs(email).
		WillReturnRows(rows)

	// Test the function
	user, err := repo.FindUserByEmail(email)
	assert.NoError(t, err)
	assert.Equal(t, expectedUser, user)
}

func TestFindUserByEmail_notfound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	email := "testnotfound@mail.com"

	// Mock SQL query to return sql.ErrNoRows to simulate a "user not found" scenario
	mock.ExpectQuery("SELECT id, username, email, password FROM users WHERE email = ?").
		WithArgs(email).
		WillReturnError(sql.ErrNoRows)

	// Test the function
	user, err := repo.FindUserByEmail(email)

	// Expecting an error for "user not found"
	assert.NoError(t, err) // No error expected since "user not found" should return nil
	assert.Nil(t, user)    // The user should be nil since it does not exist
}

func TestCheckUserByEmailRegister(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	email := "test@example.com"

	// Mock SQL query and expected result
	rows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE email = ?").
		WithArgs(email).
		WillReturnRows(rows)

	// Test the function
	exists, err := repo.CheckUserByEmailRegister(email)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestCheckUserByUsernameRegister(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "testuser"

	// Mock SQL query and expected result
	rows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE username = ?").
		WithArgs(username).
		WillReturnRows(rows)

	// Test the function
	exists, err := repo.CheckUserByUsernameRegister(username)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func timeMustParse(layout string) time.Time {
	t, err := time.Parse("2006-01-02", layout)
	if err != nil {
		panic(err)
	}
	return t
}

func TestCreateUser(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	user := &model.UserRegister{
		Username:     "newuser",
		Email:        "newuser@example.com",
		Password:     "hashedpassword",
		FistName:     "First",
		LastName:     "Last",
		Dob:          timeMustParse("2006-01-02"),
		PlaceOfBirth: "City",
		PhoneNumber:  "1234567890",
	}

	// Mock SQL query and expected result
	mock.ExpectExec("INSERT INTO users").
		WithArgs(user.Username, user.Email, user.Password, user.FistName, user.LastName, user.Dob, user.PlaceOfBirth, user.PhoneNumber).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Test the function
	result, err := repo.CreateUser(user)
	assert.NoError(t, err)

	// Verify that rows were affected
	rowsAffected, _ := result.RowsAffected()
	assert.Equal(t, int64(1), rowsAffected)
}

func TestCheckRefreshToken(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	userID := 1
	refreshToken := "sometoken"

	// Mock SQL query and expected result
	rows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users WHERE id = \\? AND refresh_token = \\?").
		WithArgs(userID, refreshToken).
		WillReturnRows(rows)

	// Test the function
	exists, err := repo.CheckRefreshToken(userID, refreshToken)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestDeleteRefreshToken(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	userID := 1
	refreshToken := "sometoken"

	// Mock SQL query and expected result
	mock.ExpectExec("DELETE FROM users WHERE id = \\? AND refresh_token = \\?").
		WithArgs(userID, refreshToken).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Test the function
	err := repo.DeleteRefreshToken(userID, refreshToken)
	assert.NoError(t, err)
}

func TestUpdateRefreshToken(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	userID := 1
	refreshToken := "newtoken"

	// Mock SQL query and expected result
	mock.ExpectExec("UPDATE users SET refresh_token = \\? WHERE id = \\?").
		WithArgs(refreshToken, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Test the function
	err := repo.UpdateRefreshToken(userID, refreshToken)
	assert.NoError(t, err)
}
