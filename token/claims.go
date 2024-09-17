package token

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"time"
)

type Claims struct {
	Id      int    `json:"id"`
	Login   string `json:"login"`
	IsAdmin bool   `json:"is_admin"`
	jwt.StandardClaims
}

func CreationUserClaims(id int, login string, isAdmin bool, duration time.Duration) (*Claims, error) {
	const op = "jwt_maker.CreationUserClaims"
	tokenId, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("error creating tokenID: %v %s", err, op)
	}
	return &Claims{
		Id:      id,
		Login:   login,
		IsAdmin: isAdmin,
		StandardClaims: jwt.StandardClaims{
			Id:        tokenId.String(),
			Subject:   fmt.Sprintf("%d", id),
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(duration).Unix(),
		},
	}, nil
}
