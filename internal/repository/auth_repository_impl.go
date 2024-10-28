package repository

import (
	"database/sql"

	"github.com/fajaramaulana/auth-serivce-payment/internal/model"
)

type UserRepositoryImpl struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &UserRepositoryImpl{db: db}
}

func (r *UserRepositoryImpl) FindUserByUsername(username string) (*model.GetUserPassword, error) {
	var user model.GetUserPassword
	query := "SELECT id, username, email, password FROM users WHERE username = ?"
	row := r.db.QueryRow(query, username)

	if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, err // Other error
	}
	return &user, nil
}

// FindUserByEmail retrieves a user by their email
func (r *UserRepositoryImpl) FindUserByEmail(email string) (*model.GetUserPassword, error) {
	var user model.GetUserPassword
	query := "SELECT id, username, email, password FROM users WHERE email = ?"
	row := r.db.QueryRow(query, email)

	if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, err // Other error
	}
	return &user, nil
}

// CheckUserByEmailRegister checks if a user with the given email already exists
func (r *UserRepositoryImpl) CheckUserByEmailRegister(email string) (bool, error) {
	query := "SELECT COUNT(*) FROM users WHERE email = ?"
	row := r.db.QueryRow(query, email)

	var count int
	if err := row.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// CheckUserByUsernameRegister checks if a user with the given username already exists
func (r *UserRepositoryImpl) CheckUserByUsernameRegister(username string) (bool, error) {
	query := "SELECT COUNT(*) FROM users WHERE username = ?"
	row := r.db.QueryRow(query, username)

	var count int
	if err := row.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// CreateUser inserts a new user into the database
func (r *UserRepositoryImpl) CreateUser(user *model.UserRegister) (result sql.Result, err error) {
	query := "INSERT INTO users (username, email, password, first_name, last_name, dob, place_of_birth, phone_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
	res, err := r.db.Exec(query, user.Username, user.Email, user.Password, user.FistName, user.LastName, user.Dob, user.PlaceOfBirth, user.PhoneNumber)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (r *UserRepositoryImpl) CheckRefreshToken(UserId int, refreshToken string) (bool, error) {
	query := "SELECT COUNT(*) FROM users WHERE id = ? AND refresh_token = ?"
	row := r.db.QueryRow(query, UserId, refreshToken)

	var count int
	if err := row.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *UserRepositoryImpl) DeleteRefreshToken(UserId int, refreshToken string) error {
	query := "DELETE FROM users WHERE id = ? AND refresh_token = ?"
	_, err := r.db.Exec(query, UserId, refreshToken)
	return err
}

func (r *UserRepositoryImpl) UpdateRefreshToken(UserId int, refreshToken string) error {
	query := "UPDATE users SET refresh_token = ? WHERE id = ?"
	_, err := r.db.Exec(query, refreshToken, UserId)
	return err
}
