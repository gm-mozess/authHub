package app

import (
	"log"
	"net/http"
)

type Application struct {
	ErrorLog *log.Logger
	InfoLog  *log.Logger
}


func (app Application) Routes() *http.ServeMux{

	mux := http.NewServeMux()
	mux.HandleFunc("/register", app.Register)
	mux.HandleFunc("/login", app.Login)

	return mux
}


func (app *Application) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		app.clientError(w, http.StatusMethodNotAllowed)
		return
	}

}

func (app *Application) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		app.clientError(w, http.StatusMethodNotAllowed)
		return
	}
}
