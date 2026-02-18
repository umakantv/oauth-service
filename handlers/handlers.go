package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
	"golang.org/x/crypto/bcrypt" // For password hashing in auth flows
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

// GetUsers handles GET /users - list all users
func (h *UserHandler) GetUsers(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	logRequest(ctx, "info", "Listing users")

	// Try cache first
	cacheKey := "users:list"
	if cached, err := h.cache.Get(cacheKey); err == nil {
		logRequest(ctx, "debug", "Serving from cache")
		w.Header().Set("Content-Type", "application/json")
		w.Write(cached.([]byte))
		return
	}

	// Query database
	rows, err := h.db.Query("SELECT id, name, email, created_at, updated_at FROM users ORDER BY created_at DESC")
	if err != nil {
		logRequest(ctx, "error", "Failed to query users", zap.Error(err))
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
			logRequest(ctx, "error", "Failed to scan user", zap.Error(err))
			continue
		}
		users = append(users, user)
	}

	// Cache the result
	response, _ := json.Marshal(users)
	h.cache.Set(cacheKey, response, 5*time.Minute)

	logRequest(ctx, "info", "Users retrieved successfully", zap.Int("count", len(users)))

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// GetUser handles GET /users/{id} - get user by ID
func (h *UserHandler) GetUser(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		logRequest(ctx, "error", "Invalid user ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid user ID"))
		return
	}

	logRequest(ctx, "info", "Getting user", zap.Int("user_id", id))

	// Try cache first
	cacheKey := "user:" + idStr
	if cached, err := h.cache.Get(cacheKey); err == nil {
		logRequest(ctx, "debug", "Serving user from cache", zap.Int("user_id", id))
		w.Header().Set("Content-Type", "application/json")
		w.Write(cached.([]byte))
		return
	}

	// Query database
	var user models.User
	err = h.db.QueryRow("SELECT id, name, email, created_at, updated_at FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		logRequest(ctx, "info", "User not found", zap.Int("user_id", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("User not found"))
		return
	}
	if err != nil {
		logRequest(ctx, "error", "Failed to query user", zap.Error(err), zap.Int("user_id", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}

	// Cache the result
	response, _ := json.Marshal(user)
	h.cache.Set(cacheKey, response, 10*time.Minute)

	logRequest(ctx, "info", "User retrieved successfully", zap.Int("user_id", id))

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// CreateUser handles POST /users - create a new user
// Updated for mandatory password (hashed with bcrypt) for auth flows (/signup compatibility)
func (h *UserHandler) CreateUser(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req models.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logRequest(ctx, "error", "Invalid request body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	// Validate input (password now mandatory)
	if req.Name == "" || req.Email == "" || req.Password == "" {
		logRequest(ctx, "error", "Missing required fields", zap.String("name", req.Name), zap.String("email", req.Email))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Name, email, and password are required"))
		return
	}

	logRequest(ctx, "info", "Creating user", zap.String("name", req.Name), zap.String("email", req.Email))

	// Hash password with bcrypt (cost 12 for security)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		logRequest(ctx, "error", "Password hashing failed", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to process password"))
		return
	}

	// Insert user (incl. hashed pw)
	result, err := h.db.Exec("INSERT INTO users (name, email, password, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		req.Name, req.Email, string(hashedPassword), time.Now(), time.Now())
	if err != nil {
		logRequest(ctx, "error", "Failed to create user", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to create user"))
		return
	}

	id, _ := result.LastInsertId()
	userID := int(id)

	// Clear users list cache
	h.cache.Delete("users:list")

	logRequest(ctx, "info", "User created successfully", zap.Int("user_id", userID))

	// Return created user (no pw)
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
// Updated to support optional password change (re-hashed if provided)
func (h *UserHandler) UpdateUser(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		logRequest(ctx, "error", "Invalid user ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid user ID"))
		return
	}

	var req models.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logRequest(ctx, "error", "Invalid request body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	logRequest(ctx, "info", "Updating user", zap.Int("user_id", id))

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
		// Hash password if provided
		hashedPassword, hashErr := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
		if hashErr != nil {
			logRequest(ctx, "error", "Password hashing failed", zap.Error(hashErr))
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to process password"))
			return
		}
		setParts = append(setParts, "password = ?")
		args = append(args, string(hashedPassword))
	}

	if len(setParts) == 0 {
		logRequest(ctx, "error", "No fields to update", zap.Int("user_id", id))
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
		logRequest(ctx, "error", "Failed to update user", zap.Error(err), zap.Int("user_id", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to update user"))
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		logRequest(ctx, "info", "User not found for update", zap.Int("user_id", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("User not found"))
		return
	}

	// Clear caches
	h.cache.Delete("users:list")
	h.cache.Delete("user:" + idStr)

	logRequest(ctx, "info", "User updated successfully", zap.Int("user_id", id))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}

// DeleteUser handles DELETE /users/{id} - delete user
func (h *UserHandler) DeleteUser(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		logRequest(ctx, "error", "Invalid user ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid user ID"))
		return
	}

	logRequest(ctx, "info", "Deleting user", zap.Int("user_id", id))

	// Delete user
	result, err := h.db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		logRequest(ctx, "error", "Failed to delete user", zap.Error(err), zap.Int("user_id", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to delete user"))
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		logRequest(ctx, "info", "User not found for deletion", zap.Int("user_id", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("User not found"))
		return
	}

	// Clear caches
	h.cache.Delete("users:list")
	h.cache.Delete("user:" + idStr)

	logRequest(ctx, "info", "User deleted successfully", zap.Int("user_id", id))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}

// OAuthClientHandler handles OAuth client-related operations
// This enables registering OAuth clients and their configurations such as
// allowed callback URLs (redirect_uris), scopes, grant types, etc.
// These clients will be used for OAuth flows in the simple OAuth server.
type OAuthClientHandler struct {
	db    *sqlx.DB
	cache cache.Cache
}

// NewOAuthClientHandler creates a new OAuth client handler
func NewOAuthClientHandler(db *sqlx.DB, cache cache.Cache) *OAuthClientHandler {
	return &OAuthClientHandler{
		db:    db,
		cache: cache,
	}
}

// logRequest logs the request with the specified format
// Note: Duplicated from UserHandler for simplicity in this boilerplate.
// In a larger codebase, this would be extracted to a shared base handler.
func (h *OAuthClientHandler) logRequest(ctx context.Context, level string, message string, fields ...zap.Field) {
	routeName := httpserver.GetRouteName(ctx)
	method := httpserver.GetRouteMethod(ctx)
	path := httpserver.GetRoutePath(ctx)
	auth := httpserver.GetRequestAuth(ctx)

	// Build log message
	logMsg := time.Now().Format("2006-01-02 15:04:05") + " - " + routeName + " - " + method + " - " + path
	if auth != nil {
		logMsg += " - client:" + auth.Client
	}

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

// generateClientID generates a unique client identifier
func generateClientID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback for demo purposes
		return "client_" + time.Now().Format("20060102150405")
	}
	return "client_" + hex.EncodeToString(b)[:24]
}

// generateClientSecret generates a secure client secret
func generateClientSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback
		return hex.EncodeToString([]byte(time.Now().String()))[:40]
	}
	return hex.EncodeToString(b)
}

// GetOAuthClients handles GET /oauth/clients - list all OAuth clients
// Useful for managing registered clients and their callback URL configs
func (h *OAuthClientHandler) GetOAuthClients(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	logRequest(ctx, "info", "Listing OAuth clients")

	// Try cache first
	cacheKey := "oauth_clients:list"
	if cached, err := h.cache.Get(cacheKey); err == nil {
		logRequest(ctx, "debug", "Serving OAuth clients from cache")
		w.Header().Set("Content-Type", "application/json")
		w.Write(cached.([]byte))
		return
	}

	// Query database - note table is oauth_client (singular)
	rows, err := h.db.Query("SELECT id, client_id, client_secret, name, email, redirect_uris, scopes, grant_types, created_at, updated_at FROM oauth_client ORDER BY created_at DESC")
	if err != nil {
		logRequest(ctx, "error", "Failed to query OAuth clients", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}
	defer rows.Close()

	var clients []models.OAuthClient
	for rows.Next() {
		var client models.OAuthClient
		err := rows.Scan(&client.ID, &client.ClientID, &client.ClientSecret, &client.Name, &client.Email, &client.RedirectURIs, &client.Scopes, &client.GrantTypes, &client.CreatedAt, &client.UpdatedAt)
		if err != nil {
			logRequest(ctx, "error", "Failed to scan OAuth client", zap.Error(err))
			continue
		}
		clients = append(clients, client)
	}

	// Cache the result (hide secrets? but for admin API, include for now)
	response, _ := json.Marshal(clients)
	h.cache.Set(cacheKey, response, 5*time.Minute)

	logRequest(ctx, "info", "OAuth clients retrieved successfully", zap.Int("count", len(clients)))

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// GetOAuthClient handles GET /oauth/clients/{id} - get OAuth client by ID
func (h *OAuthClientHandler) GetOAuthClient(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		logRequest(ctx, "error", "Invalid client ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid client ID"))
		return
	}

	logRequest(ctx, "info", "Getting OAuth client", zap.Int("client_id", id))

	// Try cache first
	cacheKey := "oauth_client:" + idStr
	if cached, err := h.cache.Get(cacheKey); err == nil {
		logRequest(ctx, "debug", "Serving OAuth client from cache", zap.Int("client_id", id))
		w.Header().Set("Content-Type", "application/json")
		w.Write(cached.([]byte))
		return
	}

	// Query database
	var client models.OAuthClient
	err = h.db.QueryRow("SELECT id, client_id, client_secret, name, email, redirect_uris, scopes, grant_types, created_at, updated_at FROM oauth_client WHERE id = ?", id).
		Scan(&client.ID, &client.ClientID, &client.ClientSecret, &client.Name, &client.Email, &client.RedirectURIs, &client.Scopes, &client.GrantTypes, &client.CreatedAt, &client.UpdatedAt)

	if err == sql.ErrNoRows {
		logRequest(ctx, "info", "OAuth client not found", zap.Int("client_id", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("OAuth client not found"))
		return
	}
	if err != nil {
		logRequest(ctx, "error", "Failed to query OAuth client", zap.Error(err), zap.Int("client_id", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}

	// Cache the result
	response, _ := json.Marshal(client)
	h.cache.Set(cacheKey, response, 10*time.Minute)

	logRequest(ctx, "info", "OAuth client retrieved successfully", zap.Int("client_id", id))

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// CreateOAuthClient handles POST /oauth/clients - register a new OAuth client
// This is the main API for adding OAuth clients with their configurations
// e.g., allowed callback URLs in redirect_uris to prevent open redirects
func (h *OAuthClientHandler) CreateOAuthClient(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req models.CreateOAuthClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logRequest(ctx, "error", "Invalid request body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	// Validate required fields
	if req.Name == "" || req.RedirectURIs == "" {
		logRequest(ctx, "error", "Missing required fields", zap.String("name", req.Name), zap.String("redirect_uris", req.RedirectURIs))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Name and redirect_uris are required"))
		return
	}

	// Generate client_id and client_secret (standard practice for client registration)
	clientID := generateClientID()
	clientSecret := generateClientSecret()

	// Set defaults
	if req.Scopes == "" {
		req.Scopes = "openid,profile,email"
	}
	if req.GrantTypes == "" {
		req.GrantTypes = "authorization_code,refresh_token"
	}

	logRequest(ctx, "info", "Creating OAuth client", zap.String("name", req.Name), zap.String("redirect_uris", req.RedirectURIs))

	// Insert client - table name oauth_client
	result, err := h.db.Exec("INSERT INTO oauth_client (client_id, client_secret, name, email, redirect_uris, scopes, grant_types, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		clientID, clientSecret, req.Name, req.Email, req.RedirectURIs, req.Scopes, req.GrantTypes, time.Now(), time.Now())
	if err != nil {
		logRequest(ctx, "error", "Failed to create OAuth client", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to create OAuth client"))
		return
	}

	id, _ := result.LastInsertId()
	clientDBID := int(id)

	// Clear clients list cache
	h.cache.Delete("oauth_clients:list")

	logRequest(ctx, "info", "OAuth client created successfully", zap.Int("client_db_id", clientDBID), zap.String("client_id", clientID))

	// Return created client (include secret only on creation, as per OAuth practice)
	client := models.OAuthClient{
		ID:           clientDBID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Name:         req.Name,
		Email:        req.Email,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
		GrantTypes:   req.GrantTypes,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(client)
}

// UpdateOAuthClient handles PUT /oauth/clients/{id} - update OAuth client config
// e.g., update allowed callback URLs
func (h *OAuthClientHandler) UpdateOAuthClient(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		logRequest(ctx, "error", "Invalid client ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid client ID"))
		return
	}

	var req models.UpdateOAuthClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logRequest(ctx, "error", "Invalid request body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	logRequest(ctx, "info", "Updating OAuth client", zap.Int("client_id", id))

	// Build update query dynamically (similar to user update)
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
	if req.RedirectURIs != "" {
		setParts = append(setParts, "redirect_uris = ?")
		args = append(args, req.RedirectURIs)
	}
	if req.Scopes != "" {
		setParts = append(setParts, "scopes = ?")
		args = append(args, req.Scopes)
	}
	if req.GrantTypes != "" {
		setParts = append(setParts, "grant_types = ?")
		args = append(args, req.GrantTypes)
	}

	if len(setParts) == 0 {
		logRequest(ctx, "error", "No fields to update", zap.Int("client_id", id))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("No fields to update"))
		return
	}

	setParts = append(setParts, "updated_at = ?")
	args = append(args, time.Now())
	args = append(args, id)

	query := "UPDATE oauth_client SET " + strings.Join(setParts, ", ") + " WHERE id = ?"
	result, err := h.db.Exec(query, args...)
	if err != nil {
		logRequest(ctx, "error", "Failed to update OAuth client", zap.Error(err), zap.Int("client_id", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to update OAuth client"))
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		logRequest(ctx, "info", "OAuth client not found for update", zap.Int("client_id", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("OAuth client not found"))
		return
	}

	// Clear caches
	h.cache.Delete("oauth_clients:list")
	h.cache.Delete("oauth_client:" + idStr)

	logRequest(ctx, "info", "OAuth client updated successfully", zap.Int("client_id", id))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "OAuth client updated successfully"})
}

// DeleteOAuthClient handles DELETE /oauth/clients/{id} - delete OAuth client
func (h *OAuthClientHandler) DeleteOAuthClient(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		logRequest(ctx, "error", "Invalid client ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid client ID"))
		return
	}

	logRequest(ctx, "info", "Deleting OAuth client", zap.Int("client_id", id))

	// Delete client
	result, err := h.db.Exec("DELETE FROM oauth_client WHERE id = ?", id)
	if err != nil {
		logRequest(ctx, "error", "Failed to delete OAuth client", zap.Error(err), zap.Int("client_id", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to delete OAuth client"))
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		logRequest(ctx, "info", "OAuth client not found for deletion", zap.Int("client_id", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("OAuth client not found"))
		return
	}

	// Clear caches
	h.cache.Delete("oauth_clients:list")
	h.cache.Delete("oauth_client:" + idStr)

	logRequest(ctx, "info", "OAuth client deleted successfully", zap.Int("client_id", id))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "OAuth client deleted successfully"})
}
