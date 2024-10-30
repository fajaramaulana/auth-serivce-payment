package utils

import "golang.org/x/crypto/bcrypt"

type PasswordHasher interface {
	Generate(password []byte, cost int) ([]byte, error)
}

type BcryptHasher struct{}

func NewPasswordHasher() PasswordHasher {
	return BcryptHasher{}
}

func (h BcryptHasher) Generate(password []byte, cost int) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, cost)
}
