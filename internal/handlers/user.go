// handlers/user.go
package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gm-mozess/authHub/internal/middleware"
	"github.com/gm-mozess/authHub/internal/models"
)

// UserHandler contains HTTP handlers for user-related endpoints
type UserHandler struct {
	userRepo *models.UserRepository
	ErrorLog *log.Logger
	InfoLog  *log.Logger
}

// NewUserHandler creates a new user handler
func NewUserHandler(userRepo *models.UserRepository, errorLog, infoLog *log.Logger) *UserHandler {
	return &UserHandler{
		userRepo: userRepo,
        ErrorLog: errorLog,
        InfoLog: infoLog,
	}
}

// UserResponse represents the user data returned to clients
type UserResponse struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

// Profile returns the authenticated user's profile
func (h *UserHandler) Profile(w http.ResponseWriter, r *http.Request) {
	// Get user ID from request context (set by auth middleware)
	userID, ok := middleware.GetUserID(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user from database
	user, err := h.userRepo.GetUserByID(userID.String())
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Return user profile (excluding sensitive data)
	response := UserResponse{
		ID:       user.ID.String(),
		Email:    user.Email,
		Username: user.Username,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
