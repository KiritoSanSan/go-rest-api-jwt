package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
	"golang.org/x/crypto/bcrypt"
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
}

type Storage struct {
	db *sql.DB
}

func New(storagePath string) (*Storage, error) {
	const op = "storage.New"
	//localtime := time.Date().Local()
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
	    balance int not null,
	    city varchar(255) not null,
	    login varchar(255) not null UNIQUE,
	    password varchar(255) not null,
	    is_admin boolean default false,
	    date_created datetime default (datetime('now', 'localtime'))
	);
`)
	if err != nil {
		return nil, fmt.Errorf("%s %s - %s", op, storagePath, err)
	}
	log.Println("Table Users created")
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS CompClub(
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    name varchar(255) not null,
	    address varchar(255) not null,
	    rating float
	);
`)
	if err != nil {
		return nil, fmt.Errorf("cant create Table CompClub %s - %s", op, err)
	}
	log.Println("Table CompClub created")
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS Packets(
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    type_room varchar(255) not null,
	    weekend boolean not null,
	    cost int not null,
	    duration_hours int not null,
	    compclub_id int not null,
	    FOREIGN KEY(compclub_id) REFERENCES CompClub(id)
	);
`)
	if err != nil {
		return nil, fmt.Errorf("cant create Table Packets %s - %s", op, err)
	}
	log.Println("Table Packets created")
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS Computers(
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    monitor varchar(255),
	    keyboard varchar(255),
	    mouse varchar(255),
	    gpu varchar(255),
	    cpu varchar(255),
	    processor varchar(255),
	    seat varchar(255),
	    devices text not null,
	    is_taken boolean not null,
	    packet_id int not null,
	    compclub_id int not null,
	    FOREIGN KEY (packet_id) REFERENCES Packets(id)
	    FOREIGN KEY (compclub_id) REFERENCES CompClub(id)
	)
`)
	if err != nil {
		return nil, fmt.Errorf("cant create Table Computers %s - %s", op, err)
	}
	log.Println("Table Computers created")
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS Users_CompClub(
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    user_id int not null,
	    compclub_id int not null,
	    foreign key (user_id) REFERENCES Users(id),
	    foreign key (compclub_id) REFERENCES CompClub(id)
	);
`)
	if err != nil {
		return nil, fmt.Errorf("cant create Table Users_CompClub %s - %s", op, err)
	}
	log.Println("Table Users_CompClub created")
	return &Storage{db: db}, nil
}

func CheckPasswordHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func HashUserPassword(password string) (string, error) {
	const op = "storage.HashUserPassword"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("cannot hash the password: %s, %s", op, err)
	}
	//return string(hashedPassword), nil
	return string(hashedPassword), nil
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

	err := CheckPasswordHash(hashedPassword, password)
	if err != nil {
		return fmt.Errorf("user with login: %s doesnt exists :%s", login, err)
	}
	return nil
}

func (s *Storage) NewUser(name string, surname string, balance int, city string, login string, password string) (int, error) {
	const op = "storage.sqlite.NewUser"
	hashedPassword, err := HashUserPassword(password)
	if err != nil {
		return 0, fmt.Errorf("cannot hash the password: %s, %s", op, err)
	}
	res, err := s.db.Exec(`
	INSERT INTO users (name,surname,balance,city,login,password)
	VALUES(?,?,?,?,?,?)`,
		name, surname, balance, city, login, hashedPassword)
	if err != nil {
		return -1, fmt.Errorf("%s %s - %s", op, name, surname, err)
	}
	last_id, err := res.LastInsertId()
	if err != nil {
		return -1, fmt.Errorf("%s - %s", op, err)
	}
	return int(last_id), nil

}

func (s *Storage) UpdateUsers(id int, name, surname string, balance int, city string) error {
	const op = "storage.sqlite.UpdateUsers"
	_, err := s.db.Exec(`
	UPDATE users
	SET name = ?, surname = ?, balance = ?, city = ?
	WHERE id = ?
	`, name, surname, balance, city, id)
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
	SELECT * FROM users
	WHERE id = ?
	`, id)
	err := row.Scan(&user.Id, &user.Name, &user.Surname, &user.Balance, &user.City)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf("User %s not found", id)
			return nil, nil
		}
		return nil, fmt.Errorf("User with id %s not found", id)
	}
	return &user, nil

}

func (s *Storage) GetUserByLogin(login string) (*User, error) {
	const op = "storage.GetUserByLogin"
	var user User
	row := s.db.QueryRow(`
	SELECT id,name,surname,balance,city,login FROM Users
	where login = ?
	`, login)
	err := row.Scan(&user.Id, &user.Name, &user.Surname, &user.Balance, &user.City, &user.Login)
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
	SELECT * FROM users
	`)
	if err != nil {
		return nil, fmt.Errorf("%s - %s", op, err)
	}
	defer rows.Close()
	for rows.Next() {
		var user User
		err = rows.Scan(&user.Id, &user.Name, &user.Surname, &user.Balance, &user.City)
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
