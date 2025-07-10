package app

import (
	"log"
	"net/http"
	"authHub/internal/models"

)

type Application struct {
	ErrorLog *log.Logger
	InfoLog  *log.Logger
	AppDB    *models.AuthHub
}

func (app Application) Routes() *http.ServeMux {

	mux := http.NewServeMux()

	mux.HandleFunc("/", app.Home)
	mux.HandleFunc("/register", app.Register)
	mux.HandleFunc("/login", app.Login)
	return mux
}

func (app *Application) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Content-Type", "application/json")
		app.ClientError(w, http.StatusMethodNotAllowed)
		return
	}

	
}

func (app *Application) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Content-Type", "application/json")
		app.ClientError(w, http.StatusMethodNotAllowed)
		return
	}
}

func (app *Application) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		app.ClientError(w, http.StatusNotFound)
		return
	}
}
