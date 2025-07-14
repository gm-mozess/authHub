package models

import (
	"authHub/pkg"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id        string
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Username  string `json:"userName"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	pkg.Validator
}

type Session struct {
	Id       string
	UserId   string
	IsActive bool
	ExpireAt time.Time
}

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	pkg.Validator
}

type AuthHub struct {
	DB *sql.DB
}

var ErrNoRecord = errors.New("no matching record found")
var ErrDuplicateEmail = errors.New("models: duplicate email")
var ErrInvalidCredentials = errors.New("models: invalid credentials")

func (m *AuthHub) InsertUser(id, firstName, lastName, username, email, password string) error {
	hash, err := pkg.HashPassword(password)
	if err != nil {
		return err
	}
	password = hash
	stmt := `INSERT INTO User(id, firstname, lastname, username, email, password)
	VALUES(?, ?, ?, ?, ?, ?)`

	_, err = m.DB.Exec(stmt, id, firstName, lastName, username, email, password)
	if err != nil {
		var mySQLError *mysql.MySQLError
		if errors.As(err, &mySQLError){
			if mySQLError.Number == 1062 && strings.Contains(mySQLError.Message, "Duplicate entry") {
				return ErrDuplicateEmail
			}
		}
		fmt.Println(err)
		return err
	}
	return err
}

func (m *AuthHub) Authenticate(email string, password string) (string, error) {
	// no matching email exists we return the ErrInvalidCredentials error.
	var id string
	var hashedPassword []byte
	stmt := "SELECT id, password FROM User WHERE email = ?"
	err := m.DB.QueryRow(stmt, email).Scan(&id, &hashedPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrInvalidCredentials
		} else {
			return "", err
		}
	}
	// Check whether the hashed password and plain-text password provided match.
	// If they don't, we return the ErrInvalidCredentials error.
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return "", ErrInvalidCredentials
		} else {
			return "", err
		}
	}
	// Otherwise, the password is correct. Return the user ID.
	return id, nil
}

func (m *AuthHub) InsertSession(session Session) error {
	_, err := m.DB.Exec("INSERT INTO Sessions (id, userId, isActive, expireAt) VALUES (?, ?, ?, ?)", session.Id, session.UserId, true, session.ExpireAt)
	if err != nil {
		return err
	}
	return nil
}

func CreateSessionCookie(userID string) (Session, error) {

	sessionID := uuid.New()
	expiration := time.Now().Add(1 * time.Hour) // Set expiration time

	session := Session{
		Id:       sessionID.String(),
		UserId:   userID,
		IsActive: true,
		ExpireAt: expiration,
	}

	return session, nil
}
