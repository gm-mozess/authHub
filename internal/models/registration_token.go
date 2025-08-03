package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type RegistToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Token 	  string
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
	tokenID := uuid.New()

	token := &RegistToken{
		ID : uuid.New(),
		UserID: userId,
		Token: tokenID.String(),
		ExpiresAt: expiresAt,
		Revoked: false,
	}

	query := `
		 INSERT INTO registration_token (id, user_id, token, expires_at, revoked)
        VALUES (?, ?, ?, ?, ?)
	`
	_, err := r.db.Exec(query, token.ID, token.UserID, token.Token, token.ExpiresAt, token.Revoked)
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
		&token.Token,
		&token.ExpiresAt,
		&token.Revoked,
	)
	if err != nil {
        return nil, err
    }
    return &token, nil
}

func (r *RegistTokenRepository) RevokeRegistToken(tokenString string) error {
	query := `
		UPDATE registration_token SET revoked = true WHERE token = ?
	`
	_,err := r.db.Exec(query, tokenString)
	return err
}
