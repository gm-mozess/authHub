// models/user.go
package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// User represents a user in our system
type User struct {
	ID           uuid.UUID
	Username     string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
	LastLogin    *time.Time
	Status       string
}

// UserRepository handles database operations for users
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// CreateUser adds a new user to the database
func (r *UserRepository) CreateUser(username, email, passwordHash string) (*User, error) {
	user := &User{
		ID:           uuid.New(),
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
		Status:       "not verified",
		CreatedAt:    time.Now(),
	}

	query := `
        INSERT INTO user (id, username, email, password, status, createdat)
        VALUES (?, ?, ?, ?, ?, ?)
    `

	_, err := r.db.Exec(query, user.ID, user.Username, user.Email, user.PasswordHash, user.Status, user.CreatedAt)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// GetUserByEmail retrieves a user by their email address
func (r *UserRepository) GetUserByEmail(email any) (*User, error) {
	query := `SELECT * FROM user WHERE email = ?`

	var user User
	var lastLogin sql.NullTime

	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Status,
		&lastLogin,
		&user.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

// GetUserByID retrieves a user by their ID
func (r *UserRepository) GetUserByID(id uuid.UUID) (*User, error) {
	query := `SELECT * FROM user WHERE id = ?`

	var user User
	var lastLogin sql.NullTime

	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
		&lastLogin,
		&user.Status,
	)

	if err != nil {
		return nil, err
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

func (r *UserRepository) UpdateStatus(userID string) error {
	query := `UPDATE user SET status ="verified" where id = ?`
	_, err := r.db.Exec(query, userID)
	return err
}

func (r *UserRepository) ResetPassword(email any, newHash_password string) error {
	query := `UPDATE user SET password = ? WHERE email = ?`
	_, err := r.db.Exec(query, email, newHash_password)
	return err
}
