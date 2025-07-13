package pkg

import (
	"database/sql"
	"errors"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func OpenDB(dns string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dns)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func GenerateUUID() string {
	var id = uuid.New()
	return uuid.UUID.String(id)
}

func Authenticate(passwordHash string, password string) bool {
	if password != passwordHash {
		return false
	}
	return true
}

func HashPassword(pass string) (string, error) {
	if len(pass) < 8 {
		return "", errors.New("password too short")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), 12)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
