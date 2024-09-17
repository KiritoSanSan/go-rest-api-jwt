package sqlite

import (
	pswrd "comp-club/password"
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
	"log"
)

type User struct {
	Id       int    `json:"id"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Balance  int    `json:"balance"`
	City     string `json:"city"`
	Login    string `json:"login"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"is_admin"`
}

type Storage struct {
	db *sql.DB
}

func New(storagePath string) (*Storage, error) {
	const op = "storage.New"
	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s %s - %s", op, storagePath, err)
	}
	log.Printf("Database created")
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS Users(
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    name varchar(255) not null,
	    surname varchar(255) not null,
	    balance int default 0,
	    city varchar(255) not null,
	    login varchar(255) not null UNIQUE,
	    password varchar(255) not null,
	    is_admin bool default false,
	    date_created datetime default (datetime('now', 'localtime'))
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_login ON Users(login);
`)
	if err != nil {
		return nil, fmt.Errorf("%s %s - %s", op, storagePath, err)
	}
	log.Println("Table Users created")

	return &Storage{db: db}, nil
}

func (s *Storage) AuthenticUser(login, password string) error {
	const op = "storage.AuthenticUser"
	var hashedPassword string
	rows, _ := s.db.Query(`
	SELECT password from Users
	WHERE login = ?
	`, login)
	for rows.Next() {
		err := rows.Scan(&hashedPassword)
		if err != nil {
			return fmt.Errorf("user with login: %s doesnt not exists :%s", login, err)
		}

	}

	err := pswrd.CheckPasswordHash(hashedPassword, password)
	if err != nil {
		return fmt.Errorf("user with login: %s doesnt exists :%s", login, err)
	}
	return nil
}

func (s *Storage) NewUser(name string, surname string, city string, login string, password string, is_admin bool) (int, error) {
	const op = "storage.sqlite.NewUser"
	hashedPassword, err := pswrd.HashUserPassword(password)
	if err != nil {
		return 0, fmt.Errorf("cannot hash the password: %s, %s", op, err)
	}
	res, err := s.db.Exec(`
	INSERT INTO users (name,surname,city,login,password,is_admin)
	VALUES(?,?,?,?,?,?)`,
		name, surname, city, login, hashedPassword, is_admin)
	if err != nil {
		return -1, fmt.Errorf("%s %s - %s", op, name, surname, err)
	}
	last_id, err := res.LastInsertId()
	if err != nil {
		return -1, fmt.Errorf("%s - %s", op, err)
	}
	return int(last_id), nil

}

func (s *Storage) UpdateUsers(id int, name, surname string, city string) error {
	const op = "storage.sqlite.UpdateUsers"
	var currentName, currentSurname, currentCity string
	err := s.db.QueryRow(`
	SELECT name,surname,city 
	FROM Users
	WHERE id = ?
	`, id).Scan(&currentName, &currentSurname, &currentCity)
	if name == "" {
		name = currentName
	}
	if surname == "" {
		surname = currentSurname
	}
	if city == "" {
		city = currentCity
	}
	_, err = s.db.Exec(`
	UPDATE users
	SET name = ?, surname = ?, city = ?
	WHERE id = ?
	`, name, surname, city, id)
	if err != nil {
		return fmt.Errorf("%s - %s", op, err)
	}
	return nil
}

func (s *Storage) DeleteUserById(id int) error {
	const op = "storage.sqlite.DeleteUsers"
	_, err := s.db.Exec(`
	DELETE FROM users
	WHERE id = ?
`, id)
	if err != nil {
		return fmt.Errorf("%s - %s", op, err)
	}
	return nil
}

func (s *Storage) GetUserById(id int) (*User, error) {
	const op = "storage.sqlite.GetUserById"
	var user User
	row := s.db.QueryRow(`
	SELECT id,name,surname,city,is_admin FROM users
	WHERE id = ?
	`, id)
	err := row.Scan(&user.Id, &user.Name, &user.Surname, &user.City, &user.IsAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf("User %s not found", id)
			return nil, nil
		}
		return nil, fmt.Errorf("user with id %s not found", id)
	}
	return &user, nil

}

func (s *Storage) GetUserByLogin(login string) (*User, error) {
	const op = "storage.GetUserByLogin"
	var user User
	row := s.db.QueryRow(`
	SELECT id,name,surname,city,login,is_admin FROM Users
	where login = ?
	`, login)
	err := row.Scan(&user.Id, &user.Name, &user.Surname, &user.City, &user.Login, &user.IsAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user %s not found", login)
		}
	}
	return &user, nil
}

func (s *Storage) GetAllUsers() ([]*User, error) {
	mylist := []*User{}

	const op = "storage.sqlite.GetAllUsers"
	rows, err := s.db.Query(`
	SELECT id,name,surname,balance,city,login FROM users
	`)
	if err != nil {
		return nil, fmt.Errorf("%s - %s", op, err)
	}
	defer rows.Close()
	for rows.Next() {
		var user User
		err = rows.Scan(&user.Id, &user.Name, &user.Surname, &user.Balance, &user.City, &user.Login)
		if err != nil {
			return nil, fmt.Errorf("%s - %s", op, err)
		}
		mylist = append(mylist, &user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s - %s", op, err)
	}
	return mylist, nil
}

//query: select
//exec: insert, update,deletion
//prepare: preparing to send many template and need db.close() "sam hz che eto"
