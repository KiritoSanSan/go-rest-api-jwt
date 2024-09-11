package handler

import (
	resp "comp-club/response"
	"comp-club/storage/sqlite"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"log"
	"net/http"
	"strconv"
	"time"
)

const (
	jwtKey = "secret"
)

type Claims struct {
	Id      int    `json:"id"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Balance int    `json:"balance"`
	City    string `json:"city"`
	Login   string `json:"login"`
	jwt.StandardClaims
}

type Request struct {
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Balance  int    `json:"balance"`
	City     string `json:"city"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

type Response struct {
	resp.Response
	Id int `json:"id"`
}

type UserResponse struct {
	resp.Response
	Id      int    `json:"id"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Balance int    `json:"balance"`
	City    string `json:"city"`
	Login   string `json:"login"`
}
type TokenResponse struct {
	resp.Response
	Token string `json:"token"`
}

type UserInput struct {
	Id       int    `json:"id"`
	Name     string `json:"name" binding:"required"`
	Surname  string `json:"surname" binding:"required"`
	Balance  int    `json:"balance" binding:"required"`
	City     string `json:"city" binding:"required"`
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}

//func GenerateJWT(user Request) (string, error) {
//	expTime := time.Now().Add(24 * time.Hour).Unix()
//	claims := &Claims{
//		Name:    user.Name,
//		Surname: user.Surname,
//		Balance: user.Balance,
//		City:    user.City,
//		Login:   user.Login,
//
//		StandardClaims: jwt.StandardClaims{
//			ExpiresAt: expTime,
//		},
//	}
//	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
//	tokenString, err := token.SignedString([]byte(jwtKey))
//	if err != nil {
//		return "", fmt.Errorf("issue with creating token: %s", err)
//	}
//	return tokenString, nil
//}

type UserManipulator interface {
	UpdateUsers(id int, name, surname string, balance int, city string) error
	DeleteUserById(id int) error
	NewUser(name string, surname string, balance int, city string, login string, password string) (int, error)
	GetAllUsers() ([]*sqlite.User, error)
	GetUserById(id int) (*sqlite.User, error)
	GetUserByLogin(login string) (*sqlite.User, error)
	AuthenticUser(login, password string) error
}

//type UserUpdater interface {
//	UpdateUsers(id int, name, surname string, balance int, city string) error
//}
//
//type UserDeleter interface {
//	DeleteUserById(id int) error
//}

//type UserSaver interface {
//	NewUser(name string, surname string, balance int, city string, login string, password string) (int, error)
//}

//type AllUsersGetter interface {
//	GetAllUsers() ([]*sqlite.User, error)
//}

//type UserByIdGetter interface {
//	GetUserById(id int) (*sqlite.User, error)
//}

//type Authenticator interface {
//	AuthenticUser(login, password string) error
//}

// todo
//
//33:43 auth user
func Login(authenticator UserManipulator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.Login"
		var exp = time.Now().Add(time.Hour * 24) //1 day
		var req Request
		err := render.DecodeJSON(r.Body, &req)
		if err != nil {
			log.Printf("[ERROR] %s - %s", op, err)
			render.JSON(w, r, resp.Error("failed to parse Request body"))
			return
		}
		err = authenticator.AuthenticUser(req.Login, req.Password)
		//log.Println("handler login: ", req.Login)
		//log.Println("handler password: ", req.Password)
		if err != nil {
			log.Printf("Error %s when authenticating user: %s", op, err)
			render.JSON(w, r, resp.Response{
				Status:  resp.StatusError,
				Message: "Error when authenticating user",
			})
			return
		}
		log.Printf("request login: %s", req.Login)
		user, err := authenticator.GetUserByLogin(req.Login)
		if err != nil {
			log.Printf("[ERROR], cannot return user by login %s - %s", op, err)
			render.JSON(w, r, resp.Response{
				Status:  resp.StatusError,
				Message: "Error when getting user: invalid request login",
			})
			return
		}
		claims := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
			Name:    user.Name,
			Surname: user.Surname,
			Balance: user.Balance,
			City:    user.City,
			Login:   user.Login,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: exp.Unix(),
				Issuer:    user.Login,
			},
		})
		//claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		//	ExpiresAt: exp.Unix(),
		//	Issuer:    user.Login,
		//})
		token, err := claims.SignedString([]byte(jwtKey))
		if err != nil {
			log.Printf("[ERROR], issue while creating token %s - %s", op, err)
			render.JSON(w, r, resp.Response{
				Status:  resp.StatusError,
				Message: "Error when creating token",
			})
			return
		}
		cookie := &http.Cookie{
			Name:     "jwtKey",
			Value:    token,
			Expires:  exp,
			HttpOnly: true, //it will be sent to frontend but ,frontend will not be able to access this cookie
		}
		http.SetCookie(w, cookie)
		render.JSON(w, r, TokenResponse{
			Response: resp.OK(),
			Token:    token,
		})
	}
}

func AuthUserToken(getter UserManipulator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.UserProfile"

		// Get the JWT token from the cookie
		cookie, err := r.Cookie("jwtKey")
		log.Printf("cookie: %v", cookie)
		if err != nil {
			log.Printf("Could not get cookie %s - %s", op, err)
			render.JSON(w, r, resp.Response{
				Status:  resp.StatusError,
				Message: "Unauthorized: Could not get cookie",
			})
			return
		}

		// Parse the JWT token and extract claims
		token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtKey), nil
		})
		log.Printf("token: %v", token)
		// Check if token is valid and no errors occurred during parsing
		if err != nil || !token.Valid {
			log.Printf("Could not parse token or token is invalid: %s", err)
			render.JSON(w, r, resp.Response{
				Status:  resp.StatusError,
				Message: "Unauthorized: Invalid token",
			})
			return
		}

		// Assert and extract claims from the token
		claims := token.Claims.(*Claims)
		if claims == nil {
			log.Printf("Could not extract claims from token: %s", op)
			render.JSON(w, r, resp.Response{
				Status:  resp.StatusError,
				Message: "Unauthorized: Invalid token claims",
			})
			return
		}

		// Retrieve user based on claims.Issuer (which contains the login)
		user, err := getter.GetUserByLogin(claims.Issuer)
		if err != nil {
			log.Printf("[ERROR] %s - error fetching user by login: %s", op, err)
			render.JSON(w, r, resp.Response{
				Status:  resp.StatusError,
				Message: "Error when fetching user by login",
			})
			return
		}

		if user == nil {
			log.Printf("[ERROR] %s - user not found for login: %s", op, claims.Issuer)
			render.JSON(w, r, resp.Response{
				Status:  resp.StatusError,
				Message: "User not found",
			})
			return
		}

		// Return the user profile in response
		render.JSON(w, r, UserResponse{
			Response: resp.Response{
				Status:  resp.StatusOK,
				Message: "Authorized",
			},
			Id:      claims.Id,
			Name:    claims.Name,
			Surname: claims.Surname,
			Balance: claims.Balance,
			City:    claims.City,
			Login:   claims.Login,
		})
	}
}

func Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwtKey")
		if err != nil {
			log.Printf("err with cookie")
		}
		cookie.Expires = time.Now().Add(-time.Hour)
		cookie.Value = ""
		cookie.HttpOnly = true
		http.SetCookie(w, cookie)
		render.JSON(w, r, resp.Response{
			Status:  resp.StatusOK,
			Message: "logout successfully",
		})
	}
}

func GetAllUsers(getter UserManipulator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.GetAllUsers"
		users, err := getter.GetAllUsers()
		if err != nil {
			log.Printf("[ERROR] %s - %s", op, err)
			return
		}
		if err := json.NewEncoder(w).Encode(users); err != nil {
			log.Printf("[ERROR] %s - %s", op, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

	}
}

func GetUserById(getter UserManipulator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.GetUserById"
		IdParam := chi.URLParam(r, "id")
		UserId, err := strconv.Atoi(IdParam)
		if err != nil {
			log.Printf("[ERROR], cannot convert into integer: %s - %s", op, err)
		}
		user, err := getter.GetUserById(UserId)
		if err != nil {
			log.Printf("[ERROR], cannot get user by id %s - %s", op, err)
		}
		if err := json.NewEncoder(w).Encode(user); err != nil {
			log.Printf("[ERROR], cannot encode user to json: %s - %s", op, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}
}

func NewUser(saver UserManipulator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.NewUser"
		var req Request
		err := render.DecodeJSON(r.Body, &req)
		if err != nil {
			log.Printf("[ERROR] %s - %s", op, err)
			render.JSON(w, r, resp.Error("failed to parse Request body"))
			return
		}
		id, err := saver.NewUser(req.Name, req.Surname, req.Balance, req.City, req.Login, req.Password)
		if err != nil {
			log.Printf("[ERROR], cannot create new User %s - %s", op, err)
			render.JSON(w, r, resp.Error("failed to create new user"))
			return
		}
		render.JSON(w, r, Response{
			Response: resp.Response{
				resp.StatusOK,
				"User Created Successfully",
			},
			Id: id,
		})
	}
}

func DeleteUser(deleter UserManipulator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.DeleteUser"
		IdParam := chi.URLParam(r, "id")
		UserId, err := strconv.Atoi(IdParam)
		if err != nil {
			log.Printf("[ERROR], cannot convert into integer: %s - %s", op, err)
			render.JSON(w, r, resp.Error("Cant convert into integer"))
			return
		}
		if err := deleter.DeleteUserById(UserId); err != nil {
			log.Printf("[ERROR], cannot delete user by id %s - %s", op, err)
			render.JSON(w, r, resp.Error("failed to delete user"))
			return
		}
		render.JSON(w, r, resp.Response{
			Status:  resp.StatusOK,
			Message: "User Deleted",
		})
	}
}

func UpdateUser(updater UserManipulator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.UpdateUser"
		IdParam := chi.URLParam(r, "id")
		UserId, err := strconv.Atoi(IdParam)
		if err != nil {
			log.Printf("[ERROR], cannot convert into integer: %s - %s", op, err)
			render.JSON(w, r, resp.Error("Cant convert into integer"))
			return
		}
		var req Request
		err = render.DecodeJSON(r.Body, &req)
		if err != nil {
			log.Printf("[ERROR] %s - %s", op, err)
			render.JSON(w, r, resp.Error("failed to parse Request body"))
			return
		}

		if err := updater.UpdateUsers(UserId, req.Name, req.Surname, req.Balance, req.City); err != nil {
			log.Printf("[ERROR],cannot update user %s - %s", op, err)
			render.JSON(w, r, resp.Error("failed to update user"))
			return
		}
		render.JSON(w, r, resp.Response{
			Status:  resp.StatusOK,
			Message: "User Updated",
		})

	}
}
