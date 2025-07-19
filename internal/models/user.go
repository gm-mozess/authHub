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
    Email        string
    Username     string
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
func (r *UserRepository) CreateUser(email, username, passwordHash string) (*User, error) {
    user := &User{
        ID:           uuid.New(),
        Email:        email,
        Username:     username,
        PasswordHash: passwordHash,
        CreatedAt:    time.Now(),
        Status: "not verified",
    }

    query := `
        INSERT INTO User (id, email, username, password, createdat, status)
        VALUES (?, ?, ?, ?, ?, ?)
    `

    _, err := r.db.Exec(query, user.ID, user.Email, user.Username, user.PasswordHash, user.CreatedAt, user.Status)
    if err != nil {
        return nil, err
    }

    return user, nil
}

// GetUserByEmail retrieves a user by their email address
func (r *UserRepository) GetUserByEmail(email string) (*User, error) {
    query := `SELECT * FROM User WHERE email = ?`

    var user User
    var lastLogin sql.NullTime

    err := r.db.QueryRow(query, email).Scan(
        &user.ID,
        &user.Email,
        &user.Username,
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
    query := `SELECT * FROM User WHERE id = ?`

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