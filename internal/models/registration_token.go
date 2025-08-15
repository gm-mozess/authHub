package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type RegistToken struct {
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

func NewRegistToken(userID uuid.UUID, token string, expiresAt time.Time, revoked bool) RegistToken {
	return RegistToken{
		UserID: userID,
		Token: token,
		ExpiresAt: expiresAt,
		Revoked: revoked,
	}
}

func (r *RegistTokenRepository) InsertRegistToken(token *RegistToken) error {
	query := `
		 INSERT INTO registration_token (id, user_id, token, expires_at, revoked)
        VALUES (?, ?, ?, FROM_UNIXTIME(?), ?)
	`
	_, err := r.db.Exec(query, token.UserID, token.Token, token.ExpiresAt, token.Revoked)
	if err != nil {
		return err
	}
	return nil
}

//id row must be deleted and user id set to primary key
func (r *RegistTokenRepository) GetRegistToken(userId string) (*RegistToken, error) {
	query := `
		SELECT * FROM registration_token WHERE user_id = ?
	`
	var token RegistToken
	err := r.db.QueryRow(query, userId).Scan(
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

func (r *RegistTokenRepository) RevokeRegistToken(userId string) error {
	query := `
		UPDATE registration_token SET revoked=true WHERE user_id = ?
	`
	_, err := r.db.Exec(query, userId)
	return err
}

func (r *RegistTokenRepository) DeleteRegistTokenHistory(userId string) error {
	query := `DELETE FROM registration_token WHERE user_id = ?`
	_, err := r.db.Exec(query, userId)
	return err
}
