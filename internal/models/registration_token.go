package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type RegistToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
	Revoked   bool
}

// RefreshTokenRepository handles database operations for refresh tokens
type RegistTokenRepository struct {
	db *sql.DB
}

func NewRegistTokenRepository(db *sql.DB) RegistTokenRepository {
	return RegistTokenRepository{db: db}
}

func (r *RegistTokenRepository) CreateRegistToken(userId uuid.UUID, ttl time.Duration) (*RegistToken, error) {
	expiresAt := time.Now().Add(ttl)
	token := &RegistToken{
		ID : uuid.New(),
		UserID:    userId,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	query := `
		 INSERT INTO refresh_tokens (id, user_id, expires_at, revoked)
        VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err := r.db.Exec(query, userId, token.ExpiresAt, token.Revoked)
	if err != nil {
		return nil, err
	}
	return token, nil

}

func (r *RegistTokenRepository) GetRegistToken(tokenString string) (*RegistToken, error) {
	query := `
		SELECT * FROM registration_token WHERE token = ?
	`
	var token RegistToken
	err := r.db.QueryRow(query, tokenString).Scan(
		&token.ID,
		&token.UserID,
		&token.ExpiresAt,
		&token.Revoked,
	)
	if err != nil {
        return nil, err
    }
    return &token, nil
}

func (r *RefreshTokenRepository) RevokeRegistToken(tokenString string) error {
	query := `
		UPDATE registration_token SET revoked = true WEHRE token = ?
	`
	_,err := r.db.Exec(query, tokenString)
	return err
}
