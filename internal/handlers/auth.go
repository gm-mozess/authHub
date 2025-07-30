package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime/debug"

	"github.com/gm-mozess/authHub/internal/auth"
	"github.com/gm-mozess/authHub/internal/middleware"
	"github.com/gm-mozess/authHub/internal/models"
)

var (
	PORT = os.Getenv("PORT")
	HOSTNAME = os.Getenv("HOST_NAME")

)

// AuthHandler contains HTTP handlers for authentication
type AuthHandler struct {
	authService *auth.AuthService
	ErrorLog    *log.Logger
	InfoLog     *log.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(authService *auth.AuthService, errorLog, infoLog *log.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		ErrorLog:    errorLog,
		InfoLog:     infoLog,
	}
}

func (h *AuthHandler) Routes(authService *auth.AuthService, ErrorLog, InfoLog *log.Logger) http.Handler {
	mux := http.NewServeMux()
	// Public routes
	mux.HandleFunc("/api/auth/register", h.Register)
	mux.HandleFunc("/api/auth/login", h.Login)
	//mux.HandleFunc("/api/auth/verify-email/send", h.VerifyEmail)
	//mux.HandleFunc("/api/auth/refresh", h.RefreshToken)

	// userHandler := handlers.NewUserHandler(userRepo, errorLog, infoLog)

	// Protected routes
	//protected := r.PathPrefix("/api").Subrouter()
	//protected.Use(middleware.AuthMiddleware(authService))
	//protected.HandleFunc("/profile", userHandler.Profile)

	return h.LogRequest(middleware.SecureHeaders(mux))
}

// RegisterRequest represents the registration payload
type RegisterRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
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
	user, err := h.authService.Register(req.Email, req.Username, req.Password)
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
		}
		return
	}

	emailToken, err := h.authService.GenerateAccessToken(user)
	if err != nil {
		h.ServerError(w, err)
		return 
	}
	link := "http://localhost:4000" + "?" + "token=" + emailToken
	listMails := []string{user.Email}
	mail := models.NewMail(link, listMails)
	err = mail.SendEmail()
	if err != nil {
		h.ServerError(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)

}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {

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
		h.ClientError(w, http.StatusUnprocessableEntity)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Attempt to login
	token, err := h.authService.Login(req.Email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			req.Validator.AddNonFieldError(auth.ErrInvalidCredentials.Error())
			response := LoginResponse{Validator: req.Validator}
			w.Header().Set("Content-Type", "application/json")
			h.ClientError(w, http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response)
			return
		} else {
			h.ServerError(w, err)
		}
		return
	}

	// Return the token
	response := LoginResponse{Token: token}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
	token, err := h.authService.RefreshAccessToken(req.RefreshToken)
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
