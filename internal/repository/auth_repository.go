package repository

import (
	"database/sql"

	"github.com/fajaramaulana/auth-serivce-payment/internal/model"
)

type UserRepository interface {
	FindUserByUsername(username string) (*model.GetUserPassword, error)
	FindUserByEmail(email string) (*model.GetUserPassword, error)

	CheckUserByUsernameRegister(username string) (bool, error)
	CheckUserByEmailRegister(email string) (bool, error)

	CreateUser(user *model.UserRegister) (result sql.Result, err error)

	CheckRefreshToken(UserId int, refreshToken string) (bool, error)
	UpdateRefreshToken(UserId int, refreshToken string) error
	DeleteRefreshToken(UserId int, refreshToken string) error
}
