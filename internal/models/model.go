package models

import (
	"database/sql"
	"errors"
)

type User struct {
	Id        string
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Username  string `json:"userName"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthHub struct {
	DB *sql.DB
}

var ErrNoRecord = errors.New("no matching record found")

// from this function you will be able to get id too
func (m *AuthHub) GetUser(username string) (*User, error) {
	stmt := `SELECT Id FROM User WHERE username == ?`
	row := m.DB.QueryRow(stmt, username)

	user := &User{}

	if err := row.Scan(&user.Id, &user.FirstName, &user.LastName, &user.Username,
		&user.Email, &user.Password); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoRecord
	}
	return user, nil
}

func (m *AuthHub) InsertUser(user User) error {
	stmt := `INSERT INTO User(Id, FirstName, LastName, Username, Email, Password)
	VALUES(?, ?, ?, ?, ?, ?)`
	_, err := m.DB.Exec(stmt, user.Id, user.FirstName, user.LastName,
		user.Username, user.Email, user.Password)

	if err != nil {
		return err
	}
	return nil
}
