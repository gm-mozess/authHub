package models

import (
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

type User struct {
	Id        uuid.UUID
	FirstName string
	LastName  string
	Username  string
	Email     string
	Password  string
}

type Login struct {
	Email    string
	Password string
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
	_, err := m.DB.Exec(stmt, user.Id, user.FirstName, user.FirstName, user.LastName,
	user.Username, user.Email, user.Password)

	if err != nil {

	}
	return nil
}