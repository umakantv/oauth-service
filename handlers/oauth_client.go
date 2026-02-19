package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// OAuthClientHandler handles OAuth client registration operations
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
func (h *OAuthClientHandler) logRequest(ctx context.Context, level string, message string, fields ...zap.Field) {
	routeName := httpserver.GetRouteName(ctx)
	method := httpserver.GetRouteMethod(ctx)
	path := httpserver.GetRoutePath(ctx)
	auth := httpserver.GetRequestAuth(ctx)

	logMsg := time.Now().Format("2006-01-02 15:04:05") + " - " + routeName + " - " + method + " - " + path
	if auth != nil {
		logMsg += " - client:" + auth.Client
	}
	logMsg += " - " + message

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

// generateClientID generates a cryptographically secure client ID
func generateClientID() (string, error) {
	b := make([]byte, 16) // 32 hex chars
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate client ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// generateClientSecret generates a cryptographically secure client secret
func generateClientSecret() (string, error) {
	b := make([]byte, 32) // 64 hex chars
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate client secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// validateRedirectURIs validates that all redirect URIs are valid absolute URLs
func validateRedirectURIs(uris []string) error {
	if len(uris) == 0 {
		return fmt.Errorf("at least one redirect_uri is required")
	}
	for _, uri := range uris {
		u, err := url.ParseRequestURI(uri)
		if err != nil {
			return fmt.Errorf("invalid redirect_uri %q: %v", uri, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("redirect_uri %q must be an absolute URL with scheme and host", uri)
		}
		if u.Fragment != "" {
			return fmt.Errorf("redirect_uri %q must not contain a fragment", uri)
		}
	}
	return nil
}

// validateGrantTypes validates the requested grant types
func validateGrantTypes(grantTypes []string) error {
	for _, gt := range grantTypes {
		if !models.AllowedGrantTypes[gt] {
			return fmt.Errorf("invalid grant_type %q; allowed: authorization_code, client_credentials, refresh_token, implicit", gt)
		}
	}
	return nil
}

// validateResponseTypes validates the requested response types
func validateResponseTypes(responseTypes []string) error {
	for _, rt := range responseTypes {
		if !models.AllowedResponseTypes[rt] {
			return fmt.Errorf("invalid response_type %q; allowed: code, token", rt)
		}
	}
	return nil
}

// validateTokenEndpointAuthMethod validates the token endpoint auth method
func validateTokenEndpointAuthMethod(method string) error {
	if !models.AllowedTokenEndpointAuthMethods[method] {
		return fmt.Errorf("invalid token_endpoint_auth_method %q; allowed: client_secret_basic, client_secret_post, none", method)
	}
	return nil
}

// RegisterClient handles POST /oauth/clients - register a new OAuth client
func (h *OAuthClientHandler) RegisterClient(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req models.CreateOAuthClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logRequest(ctx, "error", "Invalid request body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	// Validate required fields
	if req.Name == "" {
		h.logRequest(ctx, "error", "Missing client name")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("name is required"))
		return
	}

	// Validate redirect URIs
	if err := validateRedirectURIs(req.RedirectURIs); err != nil {
		h.logRequest(ctx, "error", "Invalid redirect URIs", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
		return
	}

	// Apply defaults
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}
	isConfidential := true
	if req.IsConfidential != nil {
		isConfidential = *req.IsConfidential
	}

	// Validate grant types
	if err := validateGrantTypes(req.GrantTypes); err != nil {
		h.logRequest(ctx, "error", "Invalid grant types", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
		return
	}

	// Validate response types
	if err := validateResponseTypes(req.ResponseTypes); err != nil {
		h.logRequest(ctx, "error", "Invalid response types", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
		return
	}

	// Validate token endpoint auth method
	if err := validateTokenEndpointAuthMethod(req.TokenEndpointAuthMethod); err != nil {
		h.logRequest(ctx, "error", "Invalid token endpoint auth method", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
		return
	}

	// Generate client_id and client_secret
	clientID, err := generateClientID()
	if err != nil {
		h.logRequest(ctx, "error", "Failed to generate client ID", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to generate client credentials"))
		return
	}

	clientSecret, err := generateClientSecret()
	if err != nil {
		h.logRequest(ctx, "error", "Failed to generate client secret", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to generate client credentials"))
		return
	}

	h.logRequest(ctx, "info", "Registering OAuth client", zap.String("name", req.Name), zap.String("client_id", clientID))

	// Marshal JSON arrays for storage
	redirectURIsJSON, _ := json.Marshal(req.RedirectURIs)
	grantTypesJSON, _ := json.Marshal(req.GrantTypes)
	responseTypesJSON, _ := json.Marshal(req.ResponseTypes)

	now := time.Now()

	result, err := h.db.Exec(`
		INSERT INTO oauth_clients (
			client_id, client_secret, name, description,
			redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, is_confidential, is_active,
			owner_id, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
		clientID, clientSecret, req.Name, req.Description,
		string(redirectURIsJSON), string(grantTypesJSON), string(responseTypesJSON), req.Scopes,
		req.TokenEndpointAuthMethod, isConfidential,
		req.OwnerID, now, now,
	)
	if err != nil {
		h.logRequest(ctx, "error", "Failed to register OAuth client", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to register client"))
		return
	}

	id, _ := result.LastInsertId()

	// Clear list cache
	h.cache.Delete("oauth_clients:list")

	h.logRequest(ctx, "info", "OAuth client registered successfully", zap.String("client_id", clientID), zap.Int64("id", id))

	// Build response — include the secret only on creation
	client := models.OAuthClient{
		ID:                      int(id),
		ClientID:                clientID,
		ClientSecret:            clientSecret, // returned only on registration
		Name:                    req.Name,
		Description:             req.Description,
		RedirectURIs:            string(redirectURIsJSON),
		GrantTypes:              string(grantTypesJSON),
		ResponseTypes:           string(responseTypesJSON),
		Scopes:                  req.Scopes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		IsConfidential:          isConfidential,
		IsActive:                true,
		OwnerID:                 req.OwnerID,
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(client)
}

// GetClients handles GET /oauth/clients - list all OAuth clients
func (h *OAuthClientHandler) GetClients(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	h.logRequest(ctx, "info", "Listing OAuth clients")

	// Try cache first
	cacheKey := "oauth_clients:list"
	if cached, err := h.cache.Get(cacheKey); err == nil {
		h.logRequest(ctx, "debug", "Serving from cache")
		w.Header().Set("Content-Type", "application/json")
		w.Write(cached.([]byte))
		return
	}

	rows, err := h.db.Query(`
		SELECT id, client_id, name, description,
			redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, is_confidential, is_active,
			owner_id, created_at, updated_at
		FROM oauth_clients
		ORDER BY created_at DESC`)
	if err != nil {
		h.logRequest(ctx, "error", "Failed to query OAuth clients", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}
	defer rows.Close()

	var clients []models.OAuthClient
	for rows.Next() {
		var client models.OAuthClient
		err := rows.Scan(
			&client.ID, &client.ClientID, &client.Name, &client.Description,
			&client.RedirectURIs, &client.GrantTypes, &client.ResponseTypes, &client.Scopes,
			&client.TokenEndpointAuthMethod, &client.IsConfidential, &client.IsActive,
			&client.OwnerID, &client.CreatedAt, &client.UpdatedAt,
		)
		if err != nil {
			h.logRequest(ctx, "error", "Failed to scan OAuth client", zap.Error(err))
			continue
		}
		// Do not expose client_secret in list response (it's zero-value "" and has omitempty)
		clients = append(clients, client)
	}

	response, _ := json.Marshal(clients)
	h.cache.Set(cacheKey, response, 5*time.Minute)

	h.logRequest(ctx, "info", "OAuth clients retrieved successfully", zap.Int("count", len(clients)))

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// GetClient handles GET /oauth/clients/{id} - get a single OAuth client by ID
func (h *OAuthClientHandler) GetClient(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.logRequest(ctx, "error", "Invalid client ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid client ID"))
		return
	}

	h.logRequest(ctx, "info", "Getting OAuth client", zap.Int("client_id_num", id))

	// Try cache first
	cacheKey := "oauth_client:" + idStr
	if cached, err := h.cache.Get(cacheKey); err == nil {
		h.logRequest(ctx, "debug", "Serving OAuth client from cache", zap.Int("client_id_num", id))
		w.Header().Set("Content-Type", "application/json")
		w.Write(cached.([]byte))
		return
	}

	var client models.OAuthClient
	err = h.db.QueryRow(`
		SELECT id, client_id, name, description,
			redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, is_confidential, is_active,
			owner_id, created_at, updated_at
		FROM oauth_clients WHERE id = ?`, id).Scan(
		&client.ID, &client.ClientID, &client.Name, &client.Description,
		&client.RedirectURIs, &client.GrantTypes, &client.ResponseTypes, &client.Scopes,
		&client.TokenEndpointAuthMethod, &client.IsConfidential, &client.IsActive,
		&client.OwnerID, &client.CreatedAt, &client.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		h.logRequest(ctx, "info", "OAuth client not found", zap.Int("client_id_num", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("OAuth client not found"))
		return
	}
	if err != nil {
		h.logRequest(ctx, "error", "Failed to query OAuth client", zap.Error(err), zap.Int("client_id_num", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}

	// Don't expose client_secret in GET response
	response, _ := json.Marshal(client)
	h.cache.Set(cacheKey, response, 10*time.Minute)

	h.logRequest(ctx, "info", "OAuth client retrieved successfully", zap.Int("client_id_num", id))

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// UpdateClient handles PUT /oauth/clients/{id} - update an OAuth client's configuration
func (h *OAuthClientHandler) UpdateClient(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.logRequest(ctx, "error", "Invalid client ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid client ID"))
		return
	}

	var req models.UpdateOAuthClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logRequest(ctx, "error", "Invalid request body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	h.logRequest(ctx, "info", "Updating OAuth client", zap.Int("client_id_num", id))

	// Build dynamic update query
	setParts := []string{}
	args := []interface{}{}

	if req.Name != "" {
		setParts = append(setParts, "name = ?")
		args = append(args, req.Name)
	}
	if req.Description != "" {
		setParts = append(setParts, "description = ?")
		args = append(args, req.Description)
	}
	if len(req.RedirectURIs) > 0 {
		if err := validateRedirectURIs(req.RedirectURIs); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
			return
		}
		urisJSON, _ := json.Marshal(req.RedirectURIs)
		setParts = append(setParts, "redirect_uris = ?")
		args = append(args, string(urisJSON))
	}
	if len(req.GrantTypes) > 0 {
		if err := validateGrantTypes(req.GrantTypes); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
			return
		}
		gtJSON, _ := json.Marshal(req.GrantTypes)
		setParts = append(setParts, "grant_types = ?")
		args = append(args, string(gtJSON))
	}
	if len(req.ResponseTypes) > 0 {
		if err := validateResponseTypes(req.ResponseTypes); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
			return
		}
		rtJSON, _ := json.Marshal(req.ResponseTypes)
		setParts = append(setParts, "response_types = ?")
		args = append(args, string(rtJSON))
	}
	if req.Scopes != "" {
		setParts = append(setParts, "scopes = ?")
		args = append(args, req.Scopes)
	}
	if req.TokenEndpointAuthMethod != "" {
		if err := validateTokenEndpointAuthMethod(req.TokenEndpointAuthMethod); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
			return
		}
		setParts = append(setParts, "token_endpoint_auth_method = ?")
		args = append(args, req.TokenEndpointAuthMethod)
	}
	if req.IsConfidential != nil {
		setParts = append(setParts, "is_confidential = ?")
		args = append(args, *req.IsConfidential)
	}
	if req.IsActive != nil {
		setParts = append(setParts, "is_active = ?")
		args = append(args, *req.IsActive)
	}

	if len(setParts) == 0 {
		h.logRequest(ctx, "error", "No fields to update", zap.Int("client_id_num", id))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("No fields to update"))
		return
	}

	setParts = append(setParts, "updated_at = ?")
	args = append(args, time.Now())
	args = append(args, id)

	query := "UPDATE oauth_clients SET " + strings.Join(setParts, ", ") + " WHERE id = ?"
	result, err := h.db.Exec(query, args...)
	if err != nil {
		h.logRequest(ctx, "error", "Failed to update OAuth client", zap.Error(err), zap.Int("client_id_num", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to update client"))
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		h.logRequest(ctx, "info", "OAuth client not found for update", zap.Int("client_id_num", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("OAuth client not found"))
		return
	}

	// Clear caches
	h.cache.Delete("oauth_clients:list")
	h.cache.Delete("oauth_client:" + idStr)

	h.logRequest(ctx, "info", "OAuth client updated successfully", zap.Int("client_id_num", id))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "OAuth client updated successfully"})
}

// DeleteClient handles DELETE /oauth/clients/{id} - delete (deregister) an OAuth client
func (h *OAuthClientHandler) DeleteClient(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.logRequest(ctx, "error", "Invalid client ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid client ID"))
		return
	}

	h.logRequest(ctx, "info", "Deleting OAuth client", zap.Int("client_id_num", id))

	result, err := h.db.Exec("DELETE FROM oauth_clients WHERE id = ?", id)
	if err != nil {
		h.logRequest(ctx, "error", "Failed to delete OAuth client", zap.Error(err), zap.Int("client_id_num", id))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to delete client"))
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		h.logRequest(ctx, "info", "OAuth client not found for deletion", zap.Int("client_id_num", id))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("OAuth client not found"))
		return
	}

	// Clear caches
	h.cache.Delete("oauth_clients:list")
	h.cache.Delete("oauth_client:" + idStr)

	h.logRequest(ctx, "info", "OAuth client deleted successfully", zap.Int("client_id_num", id))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "OAuth client deleted successfully"})
}

// RotateClientSecret handles POST /oauth/clients/{id}/rotate-secret - regenerate client secret
func (h *OAuthClientHandler) RotateClientSecret(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.logRequest(ctx, "error", "Invalid client ID", zap.String("id", idStr))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid client ID"))
		return
	}

	h.logRequest(ctx, "info", "Rotating client secret", zap.Int("client_id_num", id))

	// Verify client exists
	var clientID string
	err = h.db.QueryRow("SELECT client_id FROM oauth_clients WHERE id = ?", id).Scan(&clientID)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errs.NewNotFoundError("OAuth client not found"))
		return
	}
	if err != nil {
		h.logRequest(ctx, "error", "Failed to query OAuth client", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}

	// Generate new secret
	newSecret, err := generateClientSecret()
	if err != nil {
		h.logRequest(ctx, "error", "Failed to generate new secret", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to generate new secret"))
		return
	}

	_, err = h.db.Exec("UPDATE oauth_clients SET client_secret = ?, updated_at = ? WHERE id = ?",
		newSecret, time.Now(), id)
	if err != nil {
		h.logRequest(ctx, "error", "Failed to update client secret", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to rotate secret"))
		return
	}

	// Clear caches
	h.cache.Delete("oauth_clients:list")
	h.cache.Delete("oauth_client:" + idStr)

	h.logRequest(ctx, "info", "Client secret rotated successfully", zap.String("client_id", clientID))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"client_id":     clientID,
		"client_secret": newSecret,
		"message":       "Client secret rotated successfully. Store the new secret securely — it will not be shown again.",
	})
}
