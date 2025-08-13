package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/gm-mozess/authHub/internal/auth"
	"github.com/gm-mozess/authHub/internal/middleware"
)

var (
	PORT     = os.Getenv("PORT")
	HOSTNAME = os.Getenv("HOST_NAME")
)

// AuthHandler contains HTTP handlers for authentication
type AuthHandler struct {
	AuthService *auth.AuthService
	ErrorLog    *log.Logger
	InfoLog     *log.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(authService *auth.AuthService, errorLog, infoLog *log.Logger) *AuthHandler {
	return &AuthHandler{
		AuthService: authService,
		ErrorLog:    errorLog,
		InfoLog:     infoLog,
	}
}

func (h *AuthHandler) Routes(authService *auth.AuthService, ErrorLog, InfoLog *log.Logger) http.Handler {
	mux := http.NewServeMux()
	// Public routes
	mux.HandleFunc("/api/auth/register", h.Register)
	mux.HandleFunc("/api/auth/login", h.Login)
	mux.HandleFunc("/api/auth/verify-email", h.VerifyEmail)
	mux.HandleFunc("/api/auth/verify-email/send", h.GetEmailVerified)
	mux.HandleFunc("/api/auth/reset-password/send", h.GetPasswordReset)
	mux.HandleFunc("/api/auth/reset-password", h.ResetPassword)
	mux.HandleFunc("/api/auth/change-password", h.ChangePassword)

	return h.LogRequest(middleware.SecureHeaders(mux))
}

// RegisterRequest represents the registration payload
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	auth.Validator
}

// RegisterResponse contains the user data after successful registration
type RegisterResponse struct {
	Email        string            `json:"email"`
	Username     string            `json:"username"`
	FieldsErrors map[string]string `json:"fieldErrors"`
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Content-Type", "application/json")
		h.ClientError(w, http.StatusMethodNotAllowed)
		return
	}
	// Parse the request body
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.ClientError(w, http.StatusBadRequest)
	}

	req.Validator.CheckField(auth.NotBlank(req.Username), "userName", "this field cannot be blank")
	req.Validator.CheckField(auth.NotBlank(req.Email), "email", "this field cannot be blank")
	req.Validator.CheckField(auth.Matches(req.Email), "email", "This field must be a valid email address")
	req.Validator.CheckField(auth.NotBlank(req.Password), "password", "this field cannot be blank")

	req.Validator.CheckField(auth.MaxChars(req.Username, 30), "userName", "this field cannot be more than 30 characters long")
	req.Validator.CheckField(auth.MaxChars(req.Email, 100), "email", "This field cannot be more than 100 characters long")
	req.Validator.CheckField(auth.MaxChars(req.Password, 100), "password", "This field cannot be more than 100 characters long")
	req.Validator.CheckField(auth.MinChars(req.Username, 4), "userName", "this field cannot be less than 4 character")
	req.Validator.CheckField(auth.MinChars(req.Password, 8), "password", "this field cannot be less than 8")

	if !req.Validator.Valid() {
		response := RegisterResponse{
			Email:        req.Email,
			Username:     req.Username,
			FieldsErrors: req.FieldErrors,
		}
		w.Header().Set("Content-Type", "application/json")
		h.ClientError(w, http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Call the auth service to register the user
	user, err := h.AuthService.Register(req.Username, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrEmailInUse) {
			req.Validator.AddFieldError("email", auth.ErrEmailInUse.Error())
			response := RegisterResponse{
				//ID:       user.ID.String(),
				Email:        req.Email,
				Username:     req.Username,
				FieldsErrors: req.FieldErrors,
			}
			w.Header().Set("Content-Type", "application/json")
			h.ClientError(w, http.StatusConflict)
			json.NewEncoder(w).Encode(response)
		} else {
			h.ServerError(w, err)
			return
		}
		return
	}

	err = h.AuthService.SendVerificationEmail(user)
	if err != nil {
		h.ServerError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.Header().Set("Content-Type", "application/json")
		h.ClientError(w, http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query().Get("token")
	if query == "" {
		h.ClientError(w, http.StatusBadRequest)
		return
	}

	claims, err := h.AuthService.ValidateToken(query)
	if err != nil {
		h.ClientError(w, http.StatusUnauthorized)
		return
	}
	token := claims["jti"]
	id := claims["id"]
	email := claims["email"]

	registredToken, err := h.AuthService.RegistTokenRepo.GetRegistToken(token, id)
	if errors.Is(err, sql.ErrNoRows) {
		h.ClientError(w, http.StatusBadRequest)
		return
	} else if err != nil {
		h.ServerError(w, err)
		return
	}

	if registredToken.Revoked {
		h.ClientError(w, http.StatusBadRequest)
		return
	}

	err = h.AuthService.RegistTokenRepo.RevokeRegistToken(registredToken.Token, registredToken.ID.String())
	if err != nil {
		h.ServerError(w, err)
		return
	}

	err = h.AuthService.VerifyEmail(email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.ClientError(w, http.StatusUnauthorized)
			return
		} else {
			h.ServerError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// LoginRequest represents the login payload
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	auth.Validator
}

// LoginResponse contains the JWT token after successful login
type LoginResponse struct {
	Token     string `json:"token"`
	Validator auth.Validator
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.Header().Set("Allow", http.MethodPost)
        w.Header().Set("Content-Type", "application/json")
        h.ClientError(w, http.StatusMethodNotAllowed)
        return
    }

    // Parse the request body
    var req LoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.ClientError(w, http.StatusBadRequest)
        return
    }

    req.Validator.CheckField(auth.NotBlank(req.Email), "email", "this field cannot be blank")
    req.Validator.CheckField(auth.Matches(req.Email), "email", "This field must be a valid email address")
    req.Validator.CheckField(auth.NotBlank(req.Password), "password", "this field cannot be blank")

    if !req.Validator.Valid() {
        response := LoginResponse{Validator: req.Validator}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusUnprocessableEntity)
        json.NewEncoder(w).Encode(response)
        return
    }

    // Attempt to login
    idToken, accessToken, err := h.AuthService.Login(req.Email, req.Password)
    if err != nil {
        if errors.Is(err, auth.ErrInvalidCredentials) {
            req.Validator.AddNonFieldError(auth.ErrInvalidCredentials.Error())
            response := LoginResponse{Validator: req.Validator}
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusUnauthorized)
            json.NewEncoder(w).Encode(response)
            return
        } else {
            h.ServerError(w, err)
            return
        }
    }


    
    idTokenCookie := http.Cookie{
        Name:     "id_token",
        Value:    idToken,
        Path:     "/",
        MaxAge:   3600, // 1 hour in seconds
        Expires:  time.Now().Add(24 * time.Hour),
        HttpOnly: true,
        //Secure: true, // Use 'Secure: true' in production with HTTPS
        SameSite: http.SameSiteLaxMode,
    }

    accessTokenCookie := http.Cookie{
        Name:     "access_token",
        Value:    accessToken,
        Path:     "/",
        MaxAge:   3600,
        Expires:  time.Now().Add(1 * time.Hour),
        HttpOnly: true,
        //Secure: true,
        SameSite: http.SameSiteLaxMode,
    }

    http.SetCookie(w, &idTokenCookie)
    http.SetCookie(w, &accessTokenCookie)
    
    // Send success response
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (h *AuthHandler) GetEmailVerified(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Content-Type", "application/json")
		h.ClientError(w, http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie("token")
	if err != nil {
		if  errors.Is(err, http.ErrNoCookie){
			h.ClientError(w, http.StatusBadRequest)
			return
		}
	}

	claims, err := h.AuthService.ValidateToken(cookie.Value)
	if err != nil {
		h.ClientError(w, http.StatusUnauthorized)
		return
	}
	email := claims["email"].(string)
	err = h.AuthService.GetEmailVerified(email)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials){
			h.ClientError(w, http.StatusBadRequest)
			return
		}else{
			h.ServerError(w, err)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

type ResetPasswordRequest struct {
	OldPassword 			string `json:"old_password"`
	NewPassword 			string `json:"new_password"`
	PasswordConfirmation	string `json:"confirm_password"`
	Validator auth.Validator

}

type ResetPasswordResponse struct {
	Validator auth.Validator
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request){

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Content-Type", "application/json")
		h.ClientError(w, http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie("token")
	if err != nil {
		if  errors.Is(err, http.ErrNoCookie){
			h.ClientError(w, http.StatusBadRequest)
			return
		}
	}

	claims, err := h.AuthService.ValidateToken(cookie.Value)
	if err != nil {
		h.ClientError(w, http.StatusUnauthorized)
		return
	}

	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.ClientError(w, http.StatusBadRequest)
		return
	}

	req.Validator.CheckField(auth.NotBlank(req.OldPassword), "old_password", "this field cannot be blank")
	req.Validator.CheckField(auth.NotBlank(req.NewPassword), "new_password", "this field cannot be blank")
	req.Validator.CheckField(auth.NotBlank(req.PasswordConfirmation), "confirm_password", "this field cannot be blank")
	req.Validator.CheckField(auth.MaxChars(req.NewPassword, 100), "new_password", "this field cannot be more than 100 characters long")
	req.Validator.CheckField(auth.MinChars(req.NewPassword, 8), "new_password", "this field cannot be less than 8")
	req.Validator.CheckField(req.NewPassword == req.PasswordConfirmation, "confirmation_password", "passwords are not identique")
	req.Validator.CheckField(req.OldPassword != req.NewPassword, "new_password", "old and new password are same")

	response := LoginResponse{Validator: req.Validator}
	if !req.Validator.Valid() {
		h.ClientError(w, http.StatusUnprocessableEntity)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	email := claims["email"].(string)
	err = h.AuthService.ResetPassword(email, req.OldPassword, req.NewPassword)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials){
			h.ClientError(w, http.StatusForbidden)
			req.Validator.AddNonFieldError("password is not correct")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}else{
			h.ServerError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusOK)	

}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet{
		w.Header().Set("Allow", http.MethodGet)
		w.Header().Set("Content-Type", "text/html")
		h.ClientError(w, http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query().Get("token")
	if query == "" {
		h.ClientError(w, http.StatusBadRequest)
		return
	}
	_, err := h.AuthService.ValidateToken(query)
	if err != nil {
		h.ClientError(w, http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type NotifyPasswordReset struct {
	Email string `json:"email"`
	Validator auth.Validator
}

func (h *AuthHandler) GetPasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost{
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Content-Type", "text/html")
		h.ClientError(w, http.StatusMethodNotAllowed)
		return
	}

	var req NotifyPasswordReset
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.ClientError(w, http.StatusBadRequest)
		return
	}

	req.Validator.CheckField(auth.NotBlank(req.Email), "email", "this field cannot be blank")
	req.Validator.CheckField(auth.Matches(req.Email), "email", "This field must be a valid email address")

	if !req.Validator.Valid() {
		response := LoginResponse{Validator: req.Validator}
		h.ClientError(w, http.StatusUnprocessableEntity)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	err := h.AuthService.GetPasswordReset(req.Email)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials){
			h.ClientError(w, http.StatusBadRequest)
			return
		}else{
			h.ServerError(w, err)
			return
		}
	}
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse contains the new access token
type RefreshResponse struct {
	Token string `json:"token"`
}

// RefreshToken handles access token refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Parse the request body
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.ClientError(w, http.StatusBadRequest)
		return
	}

	// Attempt to refresh the token
	token, err := h.AuthService.RefreshAccessToken(req.RefreshToken)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) || errors.Is(err, auth.ErrExpiredToken) {
			h.ClientError(w, http.StatusUnauthorized)
		} else {
			h.ServerError(w, err)
		}
		return
	}

	// Return the new access token
	response := RefreshResponse{Token: token}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) ServerError(w http.ResponseWriter, err error) {
	trace := fmt.Sprintf("%s\n%s", err.Error(), debug.Stack())
	h.ErrorLog.Output(2, trace)

	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func (h *AuthHandler) ClientError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

func (h *AuthHandler) LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.InfoLog.Printf("%s - %s %s %s", r.RemoteAddr, r.Proto, r.Method, r.RequestURI)
		next.ServeHTTP(w, r)
	})
}
