package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gm-mozess/authHub/db"
	"github.com/gm-mozess/authHub/internal/auth"
	"github.com/gm-mozess/authHub/internal/handlers"
	"github.com/gm-mozess/authHub/internal/models"
	"github.com/joho/godotenv"
)

var InfoLog = log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
var ErrorLog = log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

func loadEnv() {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}
	// Check required variables
	requiredVars := []string{"JWT_SECRET", "EMAIL_ADDRESS", "PASSWORD", "SMTP_HOST", "PORT"}
	for _, v := range requiredVars {
		if os.Getenv(v) == "" {
			log.Fatalf("Required environment variable %s is not set", v)
		}
	}
}

func main() {
    // 	//here we set a default port, he can be modified with : go run . -addr=":port"
	addr := flag.String("addr", ":4000", "HTTP network address")
	dns := flag.String("dns", "net:code@/authHub?parseTime=true", "MySQL data source name")
	flag.Parse()

	// Load environment variables
	loadEnv()

	// Connect to the database
	database, err := db.Connect(*dns)
	if err != nil {
		ErrorLog.Fatal(err)
 	}

	// Create repositories
	userRepo := models.NewUserRepository(database)
	refreshTokenRepo := models.NewRefreshTokenRepository(database)
	// Create services
	authService := auth.NewAuthService(userRepo, refreshTokenRepo, os.Getenv("JWT_SECRET"), 15*time.Minute)
	// Create handlers
	authHandler := handlers.NewAuthHandler(authService, ErrorLog, InfoLog)
	srv := http.Server{
		Addr:     *addr,
		ErrorLog: ErrorLog,
		Handler:  authHandler.Routes(authService, ErrorLog, InfoLog),
	}

	InfoLog.Printf("Starting server on %s", *addr)
	err = srv.ListenAndServe()
	ErrorLog.Fatal(err)
}

