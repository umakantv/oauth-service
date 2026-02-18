package models

import "time"

// User represents a user in the system
// Password is stored hashed (bcrypt); never return plain in JSON responses
type User struct {
	ID        int       `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Email     string    `json:"email" db:"email"`
	Password  string    `json:"-" db:"password"` // Hashed; omitted from JSON
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// CreateUserRequest represents the request to create a user
// Password is now mandatory for signup/auth flows
type CreateUserRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"` // Plaintext; will be hashed in handler
}

// UpdateUserRequest represents the request to update a user
// Password optional (for reset); omit if not changing
type UpdateUserRequest struct {
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"` // Plaintext; will be hashed if provided
}

// LoginRequest for /login API (cookie session)
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// For /me response (session user)
type MeResponse struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Note: Use bcrypt for hashing; see handlers. Passwords enable cookie sessions via Redis.
