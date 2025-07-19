package db

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
)

func Connect(dns string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dns)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

