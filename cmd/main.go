package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"authHub/internal/app"
	"authHub/internal/models"
	"authHub/pkg"
)

func main() {

	//here we set a default port, he can be modified with : go run . -addr=":port"
	addr := flag.String("addr", ":4000", "HTTP network address")
	dns := flag.String("dns", "net:code@/authHub?parseTime=true", "MySQL data source name")
	flag.Parse()

	infoLog := log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	errLog := log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	db, err := pkg.OpenDB(*dns)
	if err != nil {
		errLog.Fatal(err)
	}

	defer db.Close()

	mainApp := &app.Application{
		ErrorLog: errLog,
		InfoLog:  infoLog,
		AppDB:  &models.AuthHub{DB: db},
		
	}

	srv := http.Server{
		Addr:     *addr,
		ErrorLog: errLog,
		Handler:  mainApp.Routes(),
	}

	infoLog.Printf("Starting server on %s", *addr)
	err = srv.ListenAndServe()
	errLog.Fatal(err)

}
