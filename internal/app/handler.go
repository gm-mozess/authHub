package app

import (
	"authHub/internal/models"
	"authHub/pkg"
	"encoding/json"
	"errors"
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
	mux.HandleFunc("/reset-password", app.Reset)
	mux.HandleFunc("/confirm-email", app.Validate)
	mux.HandleFunc("/logout", app.Logout)

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
	data.Id = pkg.GenerateUUID()
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		app.ClientError(w, http.StatusBadRequest)
		return
	}

	data.Validator.CheckField(pkg.NotBlank(data.FirstName), "firstName", "this field cannot be blank")
	data.Validator.CheckField(pkg.NotBlank(data.LastName), "lastName", "this field cannot be blank")
	data.Validator.CheckField(pkg.NotBlank(data.Username), "userName", "this field cannot be blank")
	data.Validator.CheckField(pkg.NotBlank(data.Email), "email", "this field cannot be blank")
	data.Validator.CheckField(pkg.Matches(data.Email, pkg.EmailRX), "email", "This field must be a valid email address")
	data.Validator.CheckField(pkg.NotBlank(data.Password), "password", "this field cannot be blank")
	data.Validator.CheckField(pkg.MaxChars(data.FirstName, 100), "firstName", "This field cannot be more than 100 characters long")
	data.Validator.CheckField(pkg.MaxChars(data.LastName, 100), "lastName", "This field cannot be more than 100 characters long")
	data.Validator.CheckField(pkg.MaxChars(data.Username, 100), "userName", "this field cannot be blank")
	data.Validator.CheckField(pkg.MaxChars(data.Email, 100), "email", "This field cannot be more than 100 characters long")
	data.Validator.CheckField(pkg.MaxChars(data.Password, 100), "password", "This field cannot be more than 100 characters long")
	data.Validator.CheckField(pkg.MinChars(data.Username, 4), "userName", "this field cannot be less than 4 character")
	data.Validator.CheckField(pkg.MinChars(data.Password, 8), "password", "this field cannot be less than 8")

	if !data.Validator.Valid() {
		for key, val := range data.Validator.FieldErrors {
			w.Header().Add(key, val)
		}
		app.ClientError(w, http.StatusUnprocessableEntity)
		return
	}

	err = app.AppDB.InsertUser(data.Id, data.FirstName, data.LastName, data.Username, data.Email, data.Password)
	if err != nil {
		if errors.Is(err, models.ErrDuplicateEmail) {
			w.Header().Add("email", "this email already exists")
			app.ClientError(w, http.StatusBadRequest)
			return
		}

		app.ServerError(w, err)
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

	var data models.Login
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		app.ClientError(w, http.StatusBadRequest)
		return
	}

	data.Validator.CheckField(pkg.NotBlank(data.Email), "email", "this field cannot be blank")
	data.Validator.CheckField(pkg.Matches(data.Email, pkg.EmailRX), "email", "This field must be a valid email address")
	data.Validator.CheckField(pkg.NotBlank(data.Password), "password", "this field cannot be blank")

	if !data.Validator.Valid() {
		for key, val := range data.Validator.FieldErrors {
			w.Header().Add(key, val)
		}
		app.ClientError(w, http.StatusUnprocessableEntity)
		return
	}

	//id, err := .....
	_, err = app.AppDB.Authenticate(data.Email, data.Password)
	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			data.Validator.AddNonFieldError("email or password is incorrect")
			w.Header().Add("credentials", "email or password is incorrect")
			app.ClientError(w, http.StatusForbidden)
			return
		} else {
			app.ServerError(w, err)
			return
		}
	}
	//handle sessions...

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *Application) Validate(w http.ResponseWriter, r *http.Request) {

}

// reset password
func (app *Application) Reset(w http.ResponseWriter, r *http.Request) {

}

func (app *Application) Logout(w http.ResponseWriter, r *http.Request) {

}

func (app *Application) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		app.ClientError(w, http.StatusNotFound)
		return
	}
}
