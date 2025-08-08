// auth/service.go
package auth

import (
	"database/sql"
	"errors"
	"time"

	"github.com/gm-mozess/authHub/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("token has expired")
	ErrEmailInUse         = errors.New("email already in use")
)

// AuthService provides authentication functionality
type AuthService struct {
	UserRepo         *models.UserRepository
	RefreshTokenRepo *models.RefreshTokenRepository
	RegistTokenRepo  *models.RegistTokenRepository
	JwtSecret        []byte
	AccessTokenTTL   time.Duration
}

// NewAuthService creates a new authentication service
func NewAuthService(userRepo *models.UserRepository, refreshTokenRepo *models.RefreshTokenRepository,
	registTokenRepo *models.RegistTokenRepository, jwtSecret string, accessTokenTTL time.Duration) *AuthService {
	return &AuthService{
		UserRepo:         userRepo,
		RefreshTokenRepo: refreshTokenRepo,
		RegistTokenRepo:  registTokenRepo,
		JwtSecret:        []byte(jwtSecret),
		AccessTokenTTL:   accessTokenTTL,
	}
}

// Register creates a new user with the provided credentials
func (s *AuthService) Register(email, username, password string) (*models.User, error) {
	// Check if user already exists
	_, err := s.UserRepo.GetUserByEmail(email)
	if err == nil {
		return nil, ErrEmailInUse
	}

	// Only proceed if the error was "user not found"
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	// Hash the password
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Create the user
	user, err := s.UserRepo.CreateUser(email, username, hashedPassword)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *AuthService) VerifyEmail(email any) error {
	user, err := s.UserRepo.GetUserByEmail(email)
	if err != nil {
		return err
	}
	err = s.UserRepo.UpdateStatus(user.ID.String())
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) SendEmail(id, email any , link string) error {
	user, err := s.UserRepo.GetUserByEmail(email)
	if err != nil {
		return err
	}

	claims, Token, err := s.GenerateAccessToken(user)
	if err != nil {
		return err
	}

	err = s.RegistTokenRepo.DeleteRegistTokenHistory(user.ID)
	if err != nil {
		return err
	}

	err = s.RegistTokenRepo.InsertRegistToken(claims)
	if err != nil {
		return err
	}

	link = link + Token
	listMails := []string{user.Email}

	var mailRepo models.MailRepository
	mail := models.NewMail(link, listMails)
	err = mailRepo.SendEmail(mail)

	if err != nil {
		return err
	}
	return nil
}

// Login authenticates a user and returns an access token
func (s *AuthService) Login(email, password string) (string, error) {
	// Get the user from the database
	user, err := s.UserRepo.GetUserByEmail(email)
	if err != nil {
		return "", ErrInvalidCredentials
	}

	// Verify the password
	if err := VerifyPassword(user.PasswordHash, password); err != nil {
		return "", ErrInvalidCredentials
	}

	// Generate an access token
	_, token, err := s.GenerateAccessToken(user)
	if err != nil {
		return "", err
	}

	return token, nil
}

// generateAccessToken creates a new JWT access token
func (s *AuthService) GenerateAccessToken(user *models.User) (jwt.MapClaims, string, error) {
	// Set the expiration time
	expirationTime := time.Now().Add(s.AccessTokenTTL)

	// Create the JWT claims
	claims := jwt.MapClaims{
		"sub":      user.ID.String(),
		"username": user.Username,
		"email":    user.Email,
		"exp":      expirationTime.Unix(),
		"iat":      time.Now().Unix(),
		"id":       uuid.New(),
		"jti":      uuid.New(),
		"revoked":  false, // revoked status
	}

	// Create the token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with our secret key
	tokenString, err := token.SignedString(s.JwtSecret)
	if err != nil {
		return nil, "", err
	}

	return claims, tokenString, nil
}

// ValidateToken verifies a JWT token and returns the claims
func (s *AuthService) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return s.JwtSecret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	// Extract and validate claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}


func (s *AuthService) ResetPassword(email any, old_password, new_password string) error {
	// Get the user from the database
	user, err := s.UserRepo.GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows){
			return ErrInvalidCredentials
		}
		return err
	}

	// Verify the password
	if err := VerifyPassword(user.PasswordHash, old_password); err != nil {
		return ErrInvalidCredentials
	}
	newHashedPassword, err := HashPassword(new_password)
	if err != nil {
		return err
	}

	err = s.UserRepo.ResetPassword(email, newHashedPassword)
	return err
}

// LoginWithRefresh authenticates a user and returns both access and refresh tokens
func (s *AuthService) LoginWithRefresh(email, password string, refreshTokenTTL time.Duration) (accessToken string, refreshToken string, err error) {
	// Get the user from the database
	user, err := s.UserRepo.GetUserByEmail(email)
	if err != nil {
		return "", "", ErrInvalidCredentials
	}

	// Verify the password
	if err := VerifyPassword(user.PasswordHash, password); err != nil {
		return "", "", ErrInvalidCredentials
	}

	// Generate an access token
	_, accessToken, err = s.GenerateAccessToken(user)
	if err != nil {
		return "", "", err
	}

	// Create a refresh token
	token, err := s.RefreshTokenRepo.CreateRefreshToken(user.ID, refreshTokenTTL)
	if err != nil {
		return "", "", err
	}

	return accessToken, token.Token, nil
}

// RefreshAccessToken creates a new access token using a refresh token
func (s *AuthService) RefreshAccessToken(refreshTokenString string) (string, error) {
	// Retrieve the refresh token
	token, err := s.RefreshTokenRepo.GetRefreshToken(refreshTokenString)
	if err != nil {
		return "", ErrInvalidToken
	}

	// Check if the token is valid
	if token.Revoked {
		return "", ErrInvalidToken
	}

	// Check if the token has expired
	if time.Now().After(token.ExpiresAt) {
		return "", ErrExpiredToken
	}

	// Get the user
	user, err := s.UserRepo.GetUserByID(token.UserID)
	if err != nil {
		return "", err
	}

	// Generate a new access token
	_, accessToken, err := s.GenerateAccessToken(user)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}
