package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"oauth-service/models"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/umakantv/go-utils/cache"
	"github.com/umakantv/go-utils/errs"
	"github.com/umakantv/go-utils/httpserver"
	logger "github.com/umakantv/go-utils/logger"
	"go.uber.org/zap"
)

// UserHandler handles user-related operations
type UserHandler struct {
	db    *sqlx.DB
	cache cache.Cache
}

// NewUserHandler creates a new user handler
func NewUserHandler(db *sqlx.DB, cache cache.Cache) *UserHandler {
	return &UserHandler{
		db:    db,
		cache: cache,
	}
}

// logRequest logs the request with the specified format
func (h *UserHandler) logRequest(ctx context.Context, level string, message string, fields ...zap.Field) {
	routeName := httpserver.GetRouteName(ctx)
	method := httpserver.GetRouteMethod(ctx)
	path := httpserver.GetRoutePath(ctx)
	auth := httpserver.GetRequestAuth(ctx)

	// Build log message
	logMsg := time.Now().Format("2006-01-02 15:04:05") + " - " + routeName + " - " + method + " - " + path
	if auth != nil {
		logMsg += " - client:" + auth.Client
	}
	logMsg += " - " + message

	// Add custom fields
	allFields := append([]zap.Field{
		zap.String("route", routeName),
		zap.String("method", method),
		zap.String("path", path),
	}, fields...)

	switch level {
	case "info":
		logger.Info(logMsg, allFields...)
	case "error":
		logger.Error(logMsg, allFields...)
	case "debug":
		logger.Debug(logMsg, allFields...)
	}
}

// hashPassword hashes a password with a random salt using SHA-256
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	saltHex := hex.EncodeToString(salt)
	hash := sha256.Sum256([]byte(saltHex + password))
	return saltHex + ":" + hex.EncodeToString(hash[:]), nil
}

// checkPassword verifies a password against its stored hash
func checkPassword(password, stored string) bool {
	parts := strings.SplitN(stored, ":", 2)
	if len(parts) != 2 {
		return false
	}
	salt := parts[0]
	hash := sha256.Sum256([]byte(salt + password))
	return hex.EncodeToString(hash[:]) == parts[1]
}

// generateSessionToken generates a cryptographically secure session token
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GetUsers handles GET /users - list all users
func (h *UserHandler) GetUsers(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	h.logRequest(ctx, "info", "Listing users")

	// Try cache first
	cacheKey := "users:list"
	if cached, err := h.cache.Get(cacheKey); err == nil {
		h.logRequest(ctx, "debug", "Serving from cache")
		w.Header().Set("Content-Type", "application/json")
		w.Write(cached.([]byte))
		return
	}

	// Query database
	rows, err := h.db.Query("SELECT id, name, email, created_at, updated_at FROM users ORDER BY created_at DESC")
	if err != nil {
		h.logRequest(ctx, "error", "Failed to query users", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			h.logRequest(ctx, "error", "Failed to scan user", zap.Error(err))
			continue
		}
		users = append(users, user)
	}

	// Cache the result
	response, _ := json.Marshal(users)
	h.cache.Set(cacheKey, response, 5*time.Minute)

	h.logRequest(ctx, "info", "Users retrieved successfully", zap.Int("count", len(users)))

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// GetUser handles GET /users/{id} - get user by ID
func (h *UserHandler) GetUser(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.logRequest(ctx, "error", "Invalid user ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid user ID"))
		return
	}

	h.logRequest(ctx, "info", "Getting user", zap.Int("user_id", id))

	// Try cache first
	cacheKey := "user:" + idStr
	if cached, err := h.cache.Get(cacheKey); err == nil {
		h.logRequest(ctx, "debug", "Serving user from cache", zap.Int("user_id", id))
		w.Header().Set("Content-Type", "application/json")
		w.Write(cached.([]byte))
		return
	}

	// Query database
	var user models.User
	err = h.db.QueryRow("SELECT id, name, email, created_at, updated_at FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		h.logRequest(ctx, "info", "User not found", zap.Int("user_id", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("User not found"))
		return
	}
	if err != nil {
		h.logRequest(ctx, "error", "Failed to query user", zap.Error(err), zap.Int("user_id", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}

	// Cache the result
	response, _ := json.Marshal(user)
	h.cache.Set(cacheKey, response, 10*time.Minute)

	h.logRequest(ctx, "info", "User retrieved successfully", zap.Int("user_id", id))

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// CreateUser handles POST /users - create a new user
func (h *UserHandler) CreateUser(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req models.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logRequest(ctx, "error", "Invalid request body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	// Validate input
	if req.Name == "" || req.Email == "" || req.Password == "" {
		h.logRequest(ctx, "error", "Missing required fields", zap.String("name", req.Name), zap.String("email", req.Email))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Name, email, and password are required"))
		return
	}

	h.logRequest(ctx, "info", "Creating user", zap.String("name", req.Name), zap.String("email", req.Email))

	// Hash the password
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		h.logRequest(ctx, "error", "Failed to hash password", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to create user"))
		return
	}

	// Insert user
	result, err := h.db.Exec("INSERT INTO users (name, email, password, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		req.Name, req.Email, hashedPassword, time.Now(), time.Now())
	if err != nil {
		h.logRequest(ctx, "error", "Failed to create user", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to create user"))
		return
	}

	id, _ := result.LastInsertId()
	userID := int(id)

	// Clear users list cache
	h.cache.Delete("users:list")

	h.logRequest(ctx, "info", "User created successfully", zap.Int("user_id", userID))

	// Return created user
	user := models.User{
		ID:        userID,
		Name:      req.Name,
		Email:     req.Email,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// UpdateUser handles PUT /users/{id} - update user
func (h *UserHandler) UpdateUser(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.logRequest(ctx, "error", "Invalid user ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid user ID"))
		return
	}

	var req models.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logRequest(ctx, "error", "Invalid request body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	h.logRequest(ctx, "info", "Updating user", zap.Int("user_id", id))

	// Build update query dynamically
	setParts := []string{}
	args := []interface{}{}

	if req.Name != "" {
		setParts = append(setParts, "name = ?")
		args = append(args, req.Name)
	}
	if req.Email != "" {
		setParts = append(setParts, "email = ?")
		args = append(args, req.Email)
	}
	if req.Password != "" {
		hashedPassword, err := hashPassword(req.Password)
		if err != nil {
			h.logRequest(ctx, "error", "Failed to hash password", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to update user"))
			return
		}
		setParts = append(setParts, "password = ?")
		args = append(args, hashedPassword)
	}

	if len(setParts) == 0 {
		h.logRequest(ctx, "error", "No fields to update", zap.Int("user_id", id))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("No fields to update"))
		return
	}

	setParts = append(setParts, "updated_at = ?")
	args = append(args, time.Now())
	args = append(args, id)

	query := "UPDATE users SET " + strings.Join(setParts, ", ") + " WHERE id = ?"
	result, err := h.db.Exec(query, args...)
	if err != nil {
		h.logRequest(ctx, "error", "Failed to update user", zap.Error(err), zap.Int("user_id", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to update user"))
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		h.logRequest(ctx, "info", "User not found for update", zap.Int("user_id", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("User not found"))
		return
	}

	// Clear caches
	h.cache.Delete("users:list")
	h.cache.Delete("user:" + idStr)

	h.logRequest(ctx, "info", "User updated successfully", zap.Int("user_id", id))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}

// DeleteUser handles DELETE /users/{id} - delete user
func (h *UserHandler) DeleteUser(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.logRequest(ctx, "error", "Invalid user ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid user ID"))
		return
	}

	h.logRequest(ctx, "info", "Deleting user", zap.Int("user_id", id))

	// Delete user
	result, err := h.db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		h.logRequest(ctx, "error", "Failed to delete user", zap.Error(err), zap.Int("user_id", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to delete user"))
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		h.logRequest(ctx, "info", "User not found for deletion", zap.Int("user_id", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("User not found"))
		return
	}

	// Clear caches
	h.cache.Delete("users:list")
	h.cache.Delete("user:" + idStr)

	h.logRequest(ctx, "info", "User deleted successfully", zap.Int("user_id", id))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}
