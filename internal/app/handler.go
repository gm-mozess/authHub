package app

import (
	"authHub/internal/models"
	"authHub/pkg"
	"encoding/json"
	"log"
	"net/http"
)

type Application struct {
	ErrorLog *log.Logger
	InfoLog  *log.Logger
	AppDB    *models.AuthHub
}

func (app Application) Routes() http.Handler {

	mux := http.NewServeMux()

	mux.HandleFunc("/", app.Home)
	mux.HandleFunc("/register", app.Register)
	mux.HandleFunc("/login", app.Login)

	return app.LogRequest(SecureHeaders(mux))
}

func (app *Application) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Content-Type", "application/json")
		app.ClientError(w, http.StatusMethodNotAllowed)
		return
	}

	var data models.User
	err := json.NewDecoder(r.Body).Decode(&data)
	data.Id = pkg.GenerateUUID()
	if err != nil {
		app.ClientError(w, http.StatusBadRequest)
		return
	}

	hash, err := pkg.HashPassword(data.Password)
	if err != nil {
		app.ClientError(w, http.StatusBadRequest)
	}
	data.Password = hash
	err = app.AppDB.InsertUser(data)
	if err != nil {
		app.ServerError(w, err)
	}
}

func (app *Application) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Content-Type", "application/json")
		app.ClientError(w, http.StatusMethodNotAllowed)
		return
	}

	var data models.Login
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		app.ClientError(w, http.StatusBadRequest)
		return
	}
	user, err := app.AppDB.GetUser(data.Email)
	if err != nil {
		app.ServerError(w, err)
	}

	authenticated := pkg.Authenticate(data.Password, user.Password)
	if !authenticated {
		app.ClientError(w, http.StatusForbidden)
		return
	}
}

func (app *Application) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		app.ClientError(w, http.StatusNotFound)
		return
	}
}


