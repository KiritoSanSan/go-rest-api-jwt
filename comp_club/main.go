package main

import (
	"comp-club/handler"
	middl "comp-club/middleware"
	"comp-club/storage/sqlite"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"log"
	"net/http"
)

func main() {
	//todo: init storage: sqlite
	//todo: init router
	//todo: init server

	// post "/users/creation creating users 	//done //checked
	// get /users/{id} info about users by id	//done //checked
	// get /users info about all				//done //checked
	// put /users/{id} update users by id 		//done //checked
	// delete /users/{id} deletion users by id	//done //checked

	//cfg := config.MustLoad()

	router := chi.NewRouter()
	storage, err := sqlite.New("storage.db")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to database")

	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.URLFormat)
	router.Use(middleware.Logger)

	router.Post("/login", handler.Login(storage))
	router.Post("/logout", handler.Logout())
	router.Post("/register", handler.NewUser(storage)) //todo: check the password while creating user, need to be al least 8 character, 1 special word and etc

	router.Post("/refresh", handler.RefreshTokenHandler)

	router.Group(func(r chi.Router) {
		r.Use(middleware.RequestID)
		r.Use(middleware.RealIP)
		r.Use(middleware.Logger)
		r.Use(middleware.URLFormat)

		r.Use(middl.GetAdminMiddlewareFunc(storage))

		r.Get("/users/{id}", handler.GetUserById(storage))
		r.Get("/users", handler.GetAllUsers(storage))
		r.Delete("/delete/{id}", handler.DeleteUser(storage))
		r.Put("/update/{id}", handler.UpdateUser(storage))
	})

	http.ListenAndServe(":8080", router)

}
