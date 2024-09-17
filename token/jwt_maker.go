package token

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"time"
)

const SecretKey = "Secret Key"

func MakeToken(id int, login string, isAdmin bool, duration time.Duration) (string, *Claims, error) {
	const op = "token.MakeToken"
	claims, err := CreationUserClaims(id, login, isAdmin, duration)
	if err != nil {
		return "", nil, fmt.Errorf("error to take claims: %s %s", err, op)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(SecretKey)) // Ensure SecretKey is a byte slice
	if err != nil {
		return "", nil, fmt.Errorf("error to sign token: %s %s", err, op)
	}
	return tokenStr, claims, nil
}

func VerifyToken(tokenStr string) (*Claims, error) {
	const op = "token.VerifyToken"
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", op)
		}
		return []byte(SecretKey), nil
	})
	log.Printf("Token got parsed: %s", token)
	if err != nil {
		return nil, fmt.Errorf("error to verify token: %s %s", err, op)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("error to verify token: %s %s", err, op)
	}
	log.Print("claims:", claims.Id)
	log.Print("claims login: ", claims.Login)
	return claims, nil
}

func AccessTokenCookie(r *http.Request) (*Claims, error) {
	const op = "token.CheckAuthByCookie"
	cookie, err := r.Cookie("access_token")
	if err != nil {
		return nil, fmt.Errorf("%s - %s", op, err)
	}
	log.Printf("Cookie got access_token: %s", cookie.Value)
	claims, err := VerifyToken(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("%s - %s", op, err)
	}
	log.Printf("Token got verified")
	log.Printf("%s - %s", op, claims)
	return claims, nil
}

func RefreshTokenCookie(r *http.Request) (*Claims, error) {
	const op = "token.CheckAuthByCookie"
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		return nil, fmt.Errorf("%s - %s", op, err)
	}
	claims, err := VerifyToken(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("%s - %s", op, err)
	}
	return claims, nil
}
