package main

import (
	"comp-club/handler"
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
	//memoryStorage := sqlite.NewMemoryStorage()
	//handler := handler.NewHandler(memoryStorage)
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.URLFormat)
	router.Use(middleware.Logger)

	//users
	router.Post("/login", handler.Login(storage))
	router.Get("/users", handler.GetAllUsers(storage))
	router.Get("/auth-user", handler.AuthUserToken(storage))
	router.Post("/logout", handler.Logout())
	router.Get("/users/{id}", handler.GetUserById(storage))
	router.Post("/register", handler.NewUser(storage))
	router.Delete("/delete/{id}", handler.DeleteUser(storage))
	router.Put("/update/{id}", handler.UpdateUser(storage))

	//CompClubs
	//router.Get("/comp-clubs",)
	//router.Get("/comp-clubs/{id}",)
	//router.Post("comp")

	http.ListenAndServe(":8080", router)

	//id, err := storage.NewUser("Beka", "Beksultan", 64.9, "Astana")
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Printf("Created user with id %d", id)

	//user, err := storage.GetUserById(1)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Println(user.Name, user.Surname, user.Balance, user.City)

	//var userlist []*sqlite.User
	//userlist, err = storage.GetAllUsers()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//for i, _ := range userlist {
	//	fmt.Print(userlist[i].Id, userlist[i].Name, userlist[i].Surname, userlist[i].Balance, userlist[i].City)
	//	fmt.Println()
	//}

	//err = storage.UpdateUsers(1, "Ivan", "Alex", 100, "Novosib")
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Printf("User with id %d has been updated", 1)

	//err = storage.DeleteUserById(1)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Println("Deleted user")
}
