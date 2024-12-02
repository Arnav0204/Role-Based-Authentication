package auth

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	models "role-based-auth/auth/models"

	"golang.org/x/crypto/bcrypt"
)

func Login(db *sql.DB, w http.ResponseWriter, r *http.Request) {

}

func Register(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var req models.User
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" || req.Role == "" {
		w.Write([]byte("all fields required"))
		return
	}

	userExists := SearchExistingUser(db, req.Email)

	if userExists {
		w.Write([]byte("User already exists"))
		return
	}

	if !validatePassword(req.Password) {
		w.Write([]byte("Password must be at least 8 characters long, include one uppercase letter, one lowercase letter, one digit, and one special character."))
		return
	}

	hashedPassword, hashError := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if hashError != nil {
		log.Println("unable to generate password hash")
		return
	}
	userPayload := models.HashedUser{
		Email:          req.Email,
		HashedPassword: string(hashedPassword),
		Role:           req.Role,
	}

	if !CreateNewUser(db, userPayload) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Failed to create new user"))
		return
	}

	//w.WriteHeader(http.StatusOK) // Sets the status code to 200
	w.Write([]byte("User successfully registered"))
}

func SearchExistingUser(db *sql.DB, email string) bool {
	search_existing_user_query := `
		SELECT COUNT(*) 
		FROM users 
		WHERE email = $1;
	`
	var count int64
	// Execute the query
	err := db.QueryRow(search_existing_user_query, email).Scan(&count)
	if err != nil {
		log.Printf("Error querying user: %v", err)
		return false
	}

	return count > 0
}

func CreateNewUser(db *sql.DB, user models.HashedUser) bool {
	create_new_user_query := `
	INSERT INTO users
   (email,password,role)
   	VALUES
	($1,$2,$3);
	`

	// Execute the query and handle potential errors
	_, err := db.Exec(create_new_user_query, user.Email, user.HashedPassword, user.Role)
	if err != nil {
		log.Printf("Error creating new user: %v", err)
		return false
	}

	return true
}

func validatePassword(password string) bool {
	// Regex to match password criteria
	passwordRegex := `^[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$`

	// Compile the regex
	re, err := regexp.MatchString(passwordRegex, password)

	if err != nil {
		log.Println("Could not match password regex")
	}

	return re
}
