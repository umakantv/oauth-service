package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"oauth-service/models"

	"github.com/jmoiron/sqlx"
	"github.com/umakantv/go-utils/cache"
	"github.com/umakantv/go-utils/errs"
	logger "github.com/umakantv/go-utils/logger"
	"go.uber.org/zap"
)

const (
	sessionCookieName = "session_token"
	sessionKeyPrefix  = "session:"
	sessionTTL        = 24 * time.Hour
)

// AuthHandler handles authentication operations (signup, login, me)
type AuthHandler struct {
	db    *sqlx.DB
	cache cache.Cache
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(db *sqlx.DB, cache cache.Cache) *AuthHandler {
	return &AuthHandler{
		db:    db,
		cache: cache,
	}
}

// Signup handles POST /signup - register a new user via the UI
func (h *AuthHandler) Signup(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req models.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	if req.Name == "" || req.Email == "" || req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Name, email, and password are required"))
		return
	}

	if len(req.Password) < 6 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Password must be at least 6 characters"))
		return
	}

	logger.Info("Signup attempt", zap.String("email", req.Email))

	// Check if user already exists
	var existingID int
	err := h.db.QueryRow("SELECT id FROM users WHERE email = ?", req.Email).Scan(&existingID)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(errs.NewValidationError("A user with this email already exists"))
		return
	}
	if err != sql.ErrNoRows {
		logger.Error("Failed to check existing user", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}

	// Hash password
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		logger.Error("Failed to hash password", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to create user"))
		return
	}

	now := time.Now()
	result, err := h.db.Exec(
		"INSERT INTO users (name, email, password, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		req.Name, req.Email, hashedPassword, now, now,
	)
	if err != nil {
		logger.Error("Failed to insert user", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to create user"))
		return
	}

	id, _ := result.LastInsertId()

	// Create session
	token, err := generateSessionToken()
	if err != nil {
		logger.Error("Failed to generate session token", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to create session"))
		return
	}

	sessionData := map[string]interface{}{
		"user_id": id,
		"email":   req.Email,
		"name":    req.Name,
	}
	sessionJSON, _ := json.Marshal(sessionData)

	if err := h.cache.Set(sessionKeyPrefix+token, string(sessionJSON), sessionTTL); err != nil {
		logger.Error("Failed to store session", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to create session"))
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	logger.Info("User signed up successfully", zap.Int64("user_id", id), zap.String("email", req.Email))

	user := models.User{
		ID:        int(id),
		Name:      req.Name,
		Email:     req.Email,
		CreatedAt: now,
		UpdatedAt: now,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// Login handles POST /login - authenticate user and create session
func (h *AuthHandler) Login(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	if req.Email == "" || req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Email and password are required"))
		return
	}

	logger.Info("Login attempt", zap.String("email", req.Email))

	// Look up user by email
	var user models.User
	err := h.db.QueryRow(
		"SELECT id, name, email, password, created_at, updated_at FROM users WHERE email = ?",
		req.Email,
	).Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errs.NewAuthenticationError("Invalid email or password"))
		return
	}
	if err != nil {
		logger.Error("Failed to query user", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}

	// Verify password
	if !checkPassword(req.Password, user.Password) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errs.NewAuthenticationError("Invalid email or password"))
		return
	}

	// Create session
	token, err := generateSessionToken()
	if err != nil {
		logger.Error("Failed to generate session token", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to create session"))
		return
	}

	sessionData := map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
		"name":    user.Name,
	}
	sessionJSON, _ := json.Marshal(sessionData)

	if err := h.cache.Set(sessionKeyPrefix+token, string(sessionJSON), sessionTTL); err != nil {
		logger.Error("Failed to store session", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to create session"))
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	logger.Info("User logged in successfully", zap.Int("user_id", user.ID), zap.String("email", user.Email))

	// Return user (password is excluded via json:"-")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// Me handles GET /me - return the current logged-in user from session cookie
func (h *AuthHandler) Me(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errs.NewAuthenticationError("Not logged in"))
		return
	}

	// Look up session in Redis
	raw, err := h.cache.Get(sessionKeyPrefix + cookie.Value)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errs.NewAuthenticationError("Session expired or invalid"))
		return
	}

	// The Redis cache returns JSON-decoded interface{}.
	// When storing a string through the cache, Get() returns a string.
	var sessionData map[string]interface{}
	switch v := raw.(type) {
	case string:
		if err := json.Unmarshal([]byte(v), &sessionData); err != nil {
			logger.Error("Failed to unmarshal session data from string", zap.Error(err))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errs.NewInternalServerError("Session error"))
			return
		}
	case map[string]interface{}:
		sessionData = v
	default:
		logger.Error(fmt.Sprintf("Unexpected session data type: %T", raw))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Session error"))
		return
	}

	// Extract user_id from session — it may be float64 (from JSON unmarshal)
	var userID int
	switch uid := sessionData["user_id"].(type) {
	case float64:
		userID = int(uid)
	case int:
		userID = uid
	case json.Number:
		id, _ := uid.Int64()
		userID = int(id)
	default:
		logger.Error(fmt.Sprintf("Unexpected user_id type in session: %T", sessionData["user_id"]))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Session error"))
		return
	}

	// Fetch fresh user data from DB
	var user models.User
	err = h.db.QueryRow(
		"SELECT id, name, email, created_at, updated_at FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errs.NewAuthenticationError("User no longer exists"))
		return
	}
	if err != nil {
		logger.Error("Failed to query user for /me", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}

	logger.Info("Serving /me", zap.Int("user_id", user.ID))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// Logout handles POST /logout - destroy session
func (h *AuthHandler) Logout(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		h.cache.Delete(sessionKeyPrefix + cookie.Value)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}
