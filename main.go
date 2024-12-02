package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	utils "role-based-auth/auth/controller"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	connstr := os.Getenv("DATABASE_URI")
	db, err := sql.Open("postgres", connstr)
	if err != nil {
		log.Fatal("connection to database failed")
	}
	defer db.Close()

	CreateTables(db)
	r := RegisterRoutes(db)
	fmt.Println("server listening on port 8080")
	httperror := http.ListenAndServe(":8080", r)
	if httperror != nil {
		log.Println("Server not started")
	}
}

func RegisterRoutes(db *sql.DB) *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		utils.Login(db, w, r)
	}).Methods("POST")

	r.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		utils.Register(db, w, r)
	}).Methods("POST")
	return r
}

func CreateTables(db *sql.DB) {
	create_users_table_query := `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,      -- Auto-incrementing primary key
			email VARCHAR(255) UNIQUE NOT NULL, -- Email must be unique
			password TEXT NOT NULL,     -- Password stored as text (hash recommended)
			role VARCHAR(50) NOT NULL   -- Role field
		);
	`
	db.Exec(create_users_table_query)

}
