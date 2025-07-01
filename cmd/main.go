package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"authHub/internal/app"

)



func main() {

	addr := flag.String("addr", ":4000", "HTTP network address")
	flag.Parse()

	infoLog:=log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	errLog:= log.New(os.Stdout, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	mainApp:= &app.Application{
		ErrorLog: errLog,
		InfoLog: infoLog,
	}

	srv := http.Server{
		Addr: *addr,
		ErrorLog: errLog,
		Handler: mainApp.Routes(),
	}


	infoLog.Printf("Starting server on %s", *addr)
	err := srv.ListenAndServe()

	errLog.Fatal(err)

}
