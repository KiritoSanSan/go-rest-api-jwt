package password

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func CheckPasswordHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func HashUserPassword(password string) (string, error) {
	const op = "storage.HashUserPassword"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("cannot hash the password: %s, %s", op, err)
	}
	return string(hashedPassword), nil
}
