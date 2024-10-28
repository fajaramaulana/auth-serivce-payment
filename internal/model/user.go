package model

import "time"

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	Password     string    `json:"password"`
	FistName     string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	Dob          string    `json:"dob"`
	PlaceOfBirth string    `json:"place_of_birth"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type GetUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	FistName string `json:"first_name"`
	LastName string `json:"last_name"`
}

type GetUserPassword struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserRegister struct {
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	Password     string    `json:"password"`
	FistName     string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	Dob          time.Time `json:"dob"`
	PlaceOfBirth string    `json:"place_of_birth"`
	PhoneNumber  string    `json:"phone_number"`
}
