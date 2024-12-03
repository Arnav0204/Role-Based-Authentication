package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	models "role-based-auth/auth/models"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var SecretKey []byte

func init() {
	SecretKey = []byte(os.Getenv("SECRET_KEY"))
}
func Login(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "unable to decode login request", http.StatusBadRequest)
	}

	if req.Email == "" || req.Password == "" {
		w.Write([]byte("all fields required"))
		return
	}

	//fetch user from database on email
	var retrivedUser *models.HashedUser
	retrivedUser, err = FetchUser(db, req.Email)
	if err != nil {
		log.Println("Error fetching user:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	//check for empty response
	if retrivedUser == nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Compare the hashed password with the plain-text password from the request
	passwordCompaisonErr := bcrypt.CompareHashAndPassword([]byte(retrivedUser.HashedPassword), []byte(req.Password))
	if passwordCompaisonErr != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	claims := jwt.MapClaims{
		"email": retrivedUser.Email,
		"role":  retrivedUser.Role,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	}

	// Create and sign the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(SecretKey)
	if err != nil {
		log.Println("Error signing token:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Respond with the signed token
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token": signedToken,
	})
}

func Register(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var req models.User
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "unable to decode register request", http.StatusBadRequest)
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

func FetchUser(db *sql.DB, email string) (*models.HashedUser, error) {
	var resp models.HashedUser
	fetch_user_query := `
		SELECT email,password,role FROM 
		users WHERE 
		email = $1;
	`
	err := db.QueryRow(fetch_user_query, email).Scan(&resp.Email, &resp.HashedPassword, &resp.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("No user found with the given email")
			return nil, nil // No user found
		}
		log.Println("Error fetching user during login:", err)
		return nil, err
	}

	return &resp, nil
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

func UserAccessibleContent(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("you are user and and can access this content"))
}

func AdminAccessibleContent(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("you are admin and and can access this content"))
}

// JWTMiddleware verifies and decodes a JWT token
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("JWTMiddleware triggered")
		// Extract the token from the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}
		log.Println("Authorization header:", authHeader)
		// Assumes "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}
		tokenString := parts[1]
		log.Println(tokenString)
		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return SecretKey, nil
		})

		if err != nil {
			log.Println("Token parsing error:", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract claims and pass them to the next handler
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Pass claims to context
			ctx := context.WithValue(r.Context(), "claims", claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		}
	})
}

// Access control middleware
func AccessControlMiddleware(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract claims from context (set by JWT middleware)
			claims, ok := r.Context().Value("claims").(jwt.MapClaims)
			if !ok {
				http.Error(w, "Unauthorized: invalid token data", http.StatusUnauthorized)
				return
			}

			// Get the role from the claims
			role, ok := claims["role"].(string)
			if !ok {
				http.Error(w, "Unauthorized: role not found in token", http.StatusUnauthorized)
				return
			}

			// Check if the user's role is in the allowed roles
			for _, allowedRole := range allowedRoles {
				if role == allowedRole {
					next.ServeHTTP(w, r)
					return
				}
			}

			// If no match, deny access
			http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
		})
	}
}
