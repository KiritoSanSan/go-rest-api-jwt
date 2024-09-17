package handler

import (
	resp "comp-club/response"
	"comp-club/storage/sqlite"
	tk "comp-club/token"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	access_duration  = time.Minute * 15
	refresh_duration = time.Hour * 24
)

type Request struct {
	Token    string `json:"token"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	City     string `json:"city"`
	Login    string `json:"login"`
	Password string `json:"password"`
	Is_Admin bool   `json:"is_admin"`
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

type UserManipulator interface {
	UpdateUsers(id int, name, surname string, city string) error
	DeleteUserById(id int) error
	NewUser(name string, surname string, city string, login string, password string, is_admin bool) (int, error)
	GetAllUsers() ([]*sqlite.User, error)
	GetUserById(id int) (*sqlite.User, error)
	GetUserByLogin(login string) (*sqlite.User, error)
	AuthenticUser(login, password string) error
}

//todo mb it will be needed and i will complete it

//func CreationUserJWT(r *http.Request) (string, error) {
//	const op = "handler.CreationUserJWT"
//	var req Request
//	err := render.DecodeJSON(r.Body, &req)
//	if err != nil {
//		return "", errors.New(op + err.Error())
//	}
//
//}

func Login(authenticator UserManipulator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.Login"
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			fields := strings.Fields(authHeader)
			if len(fields) != 2 || fields[0] != "Bearer" {
				http.Error(w, fmt.Sprintf("Error Bearer:%v", op), http.StatusUnauthorized)
				return
			}
			token := fields[1]
			claims, err := tk.VerifyToken(token)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error Veryfying token:%v", op), http.StatusUnauthorized)
				return
			}
			log.Printf("claims id:%v", claims.Id)
			_, err = authenticator.GetUserById(claims.Id)
			if err != nil {
				log.Printf("Error: %v", err)
				http.Error(w, fmt.Sprintf("Error getting user:%v", op), http.StatusUnauthorized)
				return
			}
			//accessToken, accessClaims, err := tk.MakeToken(user.Id, user.Login, user.IsAdmin, 15*time.Minute)
			//if err != nil {
			//	log.Printf("[ERROR], cannot return user by login %s - %s", op, err)
			//	http.Error(w, "error when creating access token in login", 404)
			//	return
			//}
			//refreshToken, refreshClaims, err := tk.MakeToken(user.Id, user.Login, user.IsAdmin, 24*time.Hour)
			//if err != nil {
			//	http.Error(w, "error when creating refresh token in login", 404)
			//	return
			//}
			//
			//accessCookie := &http.Cookie{
			//	Name:     "access_token",
			//	Value:    accessToken,
			//	Expires:  time.Unix(accessClaims.ExpiresAt, 0),
			//	HttpOnly: true, //it will be sent to frontend but ,frontend will not be able to access this cookie
			//	Path:     "/",
			//}
			//http.SetCookie(w, accessCookie)
			//
			//refreshCookie := &http.Cookie{
			//	Name:     "refresh_token",
			//	Value:    refreshToken,
			//	Expires:  time.Unix(refreshClaims.ExpiresAt, 0),
			//	HttpOnly: true,
			//	Path:     "/refresh",
			//}
			//http.SetCookie(w, refreshCookie)
			//
			render.JSON(w, r, resp.Response{
				Status:  resp.StatusOK,
				Message: "Successfully Logged In",
			})
			return

		}
		var req Request
		err := render.DecodeJSON(r.Body, &req)
		if err != nil {
			log.Printf("[ERROR] %s - %s", op, err)
			render.JSON(w, r, resp.Error("failed to parse Request body"))
			return
		}
		err = authenticator.AuthenticUser(req.Login, req.Password)

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
		log.Print("User that got my request:", user.Login)
		accessToken, accessClaims, err := tk.MakeToken(user.Id, user.Login, user.IsAdmin, access_duration)
		if err != nil {
			log.Printf("[ERROR], cannot return user by login %s - %s", op, err)
			http.Error(w, "error when creating access token in login", 404)
			return
		}
		refreshToken, refreshClaims, err := tk.MakeToken(user.Id, user.Login, user.IsAdmin, refresh_duration)
		if err != nil {
			http.Error(w, "error when creating refresh token in login", 404)
			return
		}

		accessCookie := &http.Cookie{
			Name:     "access_token",
			Value:    accessToken,
			Expires:  time.Unix(accessClaims.ExpiresAt, 0),
			HttpOnly: true, //it will be sent to frontend but ,frontend will not be able to access this cookie
			Path:     "/",
		}
		http.SetCookie(w, accessCookie)

		refreshCookie := &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Expires:  time.Unix(refreshClaims.ExpiresAt, 0),
			HttpOnly: true,
			Path:     "/refresh",
		}
		http.SetCookie(w, refreshCookie)

		render.JSON(w, r, TokenResponse{
			Response: resp.OK(),
			Token:    accessToken,
		})
		return
	}
}

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	const op = "handler.RefreshToken"
	refreshCookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "refresh token missing", http.StatusUnauthorized)
		return
	}
	refreshClaims, err := tk.VerifyToken(refreshCookie.Value)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	accessToken, accessClaims, err := tk.MakeToken(refreshClaims.Id, refreshClaims.Login, refreshClaims.IsAdmin, 15*time.Minute)
	if err != nil {
		http.Error(w, "error when creating access token in login", 404)
		return
	}
	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Expires:  time.Unix(accessClaims.ExpiresAt, 0),
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, accessCookie)
}

func Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.Logout"
		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    "",
			Expires:  time.Now(),
			HttpOnly: true,
			Path:     "/",
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Expires:  time.Now(),
			HttpOnly: true,
			Path:     "/refresh",
		})
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
		for _, v := range users {
			render.JSON(w, r, UserResponse{
				Response: resp.Response{
					Status: resp.StatusOK,
				},
				Name:    v.Name,
				Surname: v.Surname,
				City:    v.City,
				Login:   v.Login,
			})
		}
		return

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
		render.JSON(w, r, UserResponse{
			Id:      UserId,
			Name:    user.Name,
			Surname: user.Surname,
			Balance: user.Balance,
			City:    user.City,
			Login:   user.Login,
		})

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
		id, err := saver.NewUser(req.Name, req.Surname, req.City, req.Login, req.Password, req.Is_Admin)
		if err != nil {
			log.Printf("[ERROR], cannot create new User %s - %s", op, err)
			render.JSON(w, r, resp.Error("failed to create new user"))
			return
		}
		render.JSON(w, r, Response{
			Response: resp.Response{
				Status:  resp.StatusOK,
				Message: "User Created Successfully",
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

		if err := updater.UpdateUsers(UserId, req.Name, req.Surname, req.City); err != nil {
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
