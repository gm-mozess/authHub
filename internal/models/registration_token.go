package models

import (
	"database/sql"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type RegistToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Token     string
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

func (r *RegistTokenRepository) InsertRegistToken(claims jwt.MapClaims) error {
	userID := claims["sub"]
	token := claims["jti"]
	id := claims["id"]
	expiresAt := claims["exp"]
	revoked := claims["revoked"]

	query := `
		 INSERT INTO registration_token (id, user_id, token, expires_at, revoked)
        VALUES (?, ?, ?, FROM_UNIXTIME(?), ?)
	`
	_, err := r.db.Exec(query, id, userID, token, expiresAt, revoked)
	if err != nil {
		return err
	}
	return nil
}

func (r *RegistTokenRepository) GetRegistToken(tokenString, id any) (*RegistToken, error) {
	query := `
		SELECT * FROM registration_token WHERE token = ? and id = ?
	`
	var token RegistToken
	err := r.db.QueryRow(query, tokenString, id).Scan(
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

func (r *RegistTokenRepository) RevokeRegistToken(tokenString, id string) error {
	query := `
		UPDATE registration_token SET revoked=true WHERE token = ? and id = ?
	`
	_, err := r.db.Exec(query, tokenString, id)
	return err
}

func (r *RegistTokenRepository) DeleteRegistTokenHistory(userID any) error {
	query := `DELETE FROM registration_token WHERE user_id = ?`
	_, err := r.db.Exec(query, userID)
	return err
}
