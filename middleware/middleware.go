package middleware

import (
	"comp-club/handler"
	tk "comp-club/token"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func GetAdminMiddlewareFunc(authenticator handler.UserManipulator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			const op = "middleware.GetAdminMiddleware"
			// read the authorization header
			// verify the token
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {

				accessClaim, err := tk.AccessTokenCookie(r)
				if err != nil {
					http.Error(w, fmt.Sprintf("User unauthorized:%s", op), http.StatusUnauthorized)
					return
				}
				log.Printf("cookie accessclaim: %v ", accessClaim.Login)
				user, err := authenticator.GetUserByLogin(accessClaim.Login)
				if err != nil {
					http.Error(w, fmt.Sprintf("error authenticating user: %v", err), http.StatusUnauthorized)
					return
				}
				log.Printf("user: %v", user)
				if !user.IsAdmin {
					http.Error(w, "user is not an admin", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			} else {
				claims, err := verifyClaimsFromAuthHeader(r)
				if err != nil {
					http.Error(w, fmt.Sprintf("error verifying token: %v", err), http.StatusUnauthorized)
					return
				}
				log.Printf("Bearer claim: %v", claims.Login)
				user, err := authenticator.GetUserByLogin(claims.Login)
				if err != nil {
					http.Error(w, fmt.Sprintf("error authenticating user: %v", err), http.StatusUnauthorized)
					return
				}
				if !user.IsAdmin {
					http.Error(w, "user is not an admin", http.StatusForbidden)
					return
				}

				// pass the payload/claims down the context

				next.ServeHTTP(w, r)
			}
		})

	}
}

func GetAuthMiddlewareFunc(authenticator handler.UserManipulator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// read the authorization header
			// verify the token
			claims, err := verifyClaimsFromAuthHeader(r)
			if err != nil {
				http.Error(w, fmt.Sprintf("error verifying token: %v", err), http.StatusUnauthorized)
				return
			}
			_, err = authenticator.GetUserByLogin(claims.Login)
			if err != nil {
				http.Error(w, fmt.Sprintf("error getting user: %v", err), http.StatusUnauthorized)
				return
			}

			// pass the payload/claims down the context
			next.ServeHTTP(w, r)
		})

	}
}

func verifyClaimsFromAuthHeader(r *http.Request) (*tk.Claims, error) {
	authHeader := r.Header.Get("Authorization")
	//if authHeader == "" {
	//	return nil, fmt.Errorf("authorization header is missing")
	//}

	fields := strings.Fields(authHeader)
	if len(fields) != 2 || fields[0] != "Bearer" {
		return nil, fmt.Errorf("invalid authorization header")
	}

	token := fields[1]
	claims, err := tk.VerifyToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return claims, nil
}
