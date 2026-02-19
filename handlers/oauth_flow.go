package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	authCodeKeyPrefix     = "authcode:"
	authCodeTTL           = 10 * time.Minute
	accessTokenKeyPrefix  = "access_token:"
	accessTokenTTL        = 1 * time.Hour
	refreshTokenKeyPrefix = "refresh_token:"
	refreshTokenTTL       = 30 * 24 * time.Hour // 30 days
)

// OAuthFlowHandler handles the OAuth 2.0 authorization flow
type OAuthFlowHandler struct {
	db    *sqlx.DB
	cache cache.Cache
}

// NewOAuthFlowHandler creates a new OAuth flow handler
func NewOAuthFlowHandler(db *sqlx.DB, cache cache.Cache) *OAuthFlowHandler {
	return &OAuthFlowHandler{
		db:    db,
		cache: cache,
	}
}

// generateCode generates a cryptographically secure random code
func generateCode(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// getUserIDFromSession extracts user_id from the session cookie via Redis
func (h *OAuthFlowHandler) getUserIDFromSession(r *http.Request) (int, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return 0, fmt.Errorf("no session cookie")
	}

	raw, err := h.cache.Get(sessionKeyPrefix + cookie.Value)
	if err != nil {
		return 0, fmt.Errorf("session expired or invalid")
	}

	var sessionData map[string]interface{}
	switch v := raw.(type) {
	case string:
		if err := json.Unmarshal([]byte(v), &sessionData); err != nil {
			return 0, fmt.Errorf("invalid session data")
		}
	case map[string]interface{}:
		sessionData = v
	default:
		return 0, fmt.Errorf("unexpected session type")
	}

	switch uid := sessionData["user_id"].(type) {
	case float64:
		return int(uid), nil
	case int:
		return uid, nil
	case json.Number:
		id, _ := uid.Int64()
		return int(id), nil
	}
	return 0, fmt.Errorf("invalid user_id in session")
}

// RegisterClientFromUI handles POST /oauth/register-client — cookie-based, sets owner_id from session
func (h *OAuthFlowHandler) RegisterClientFromUI(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	userID, err := h.getUserIDFromSession(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errs.NewAuthenticationError("Not logged in"))
		return
	}

	var req models.CreateOAuthClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	if req.Name == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("name is required"))
		return
	}
	if err := validateRedirectURIs(req.RedirectURIs); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
		return
	}

	// Defaults
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

	if err := validateGrantTypes(req.GrantTypes); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
		return
	}
	if err := validateResponseTypes(req.ResponseTypes); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
		return
	}
	if err := validateTokenEndpointAuthMethod(req.TokenEndpointAuthMethod); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError(err.Error()))
		return
	}

	clientID, err := generateClientID()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to generate client credentials"))
		return
	}
	clientSecret, err := generateClientSecret()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to generate client credentials"))
		return
	}

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
		userID, now, now,
	)
	if err != nil {
		logger.Error("Failed to register OAuth client from UI", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to register client"))
		return
	}

	id, _ := result.LastInsertId()
	h.cache.Delete("oauth_clients:list")

	logger.Info("OAuth client registered from UI",
		zap.String("client_id", clientID), zap.Int("owner_id", userID))

	client := models.OAuthClient{
		ID:                      int(id),
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		Name:                    req.Name,
		Description:             req.Description,
		RedirectURIs:            string(redirectURIsJSON),
		GrantTypes:              string(grantTypesJSON),
		ResponseTypes:           string(responseTypesJSON),
		Scopes:                  req.Scopes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		IsConfidential:          isConfidential,
		IsActive:                true,
		OwnerID:                 &userID,
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(client)
}

// Initialize handles GET /oauth/initialize — serves index.html (the UI handles the rest via JS)
func (h *OAuthFlowHandler) Initialize(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/index.html")
}

// ValidateInitialize handles GET /oauth/validate-init — JSON API that validates the OAuth params
// and returns client info + logged-in user info for the consent screen
func (h *OAuthFlowHandler) ValidateInitialize(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	clientIDParam := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	responseType := r.URL.Query().Get("response_type")
	state := r.URL.Query().Get("state")

	if clientIDParam == "" || redirectURI == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("client_id and redirect_uri are required"))
		return
	}
	if responseType == "" {
		responseType = "code"
	}

	// Look up client
	var client models.OAuthClient
	err := h.db.QueryRow(`
		SELECT id, client_id, name, description, redirect_uris, grant_types,
			response_types, scopes, is_active
		FROM oauth_clients WHERE client_id = ?`, clientIDParam).Scan(
		&client.ID, &client.ClientID, &client.Name, &client.Description,
		&client.RedirectURIs, &client.GrantTypes, &client.ResponseTypes,
		&client.Scopes, &client.IsActive,
	)
	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Unknown client_id"))
		return
	}
	if err != nil {
		logger.Error("Failed to look up client for OAuth init", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}
	if !client.IsActive {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("This OAuth client has been deactivated"))
		return
	}

	// Verify redirect_uri matches one of the registered URIs
	var registeredURIs []string
	json.Unmarshal([]byte(client.RedirectURIs), &registeredURIs)
	matched := false
	for _, uri := range registeredURIs {
		if uri == redirectURI {
			matched = true
			break
		}
	}
	if !matched {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError(
			fmt.Sprintf("redirect_uri %q does not match any registered redirect URIs for this client", redirectURI)))
		return
	}

	// Check if user is logged in
	var user *models.User
	userID, err := h.getUserIDFromSession(r)
	if err == nil {
		var u models.User
		dbErr := h.db.QueryRow(
			"SELECT id, name, email, created_at, updated_at FROM users WHERE id = ?", userID,
		).Scan(&u.ID, &u.Name, &u.Email, &u.CreatedAt, &u.UpdatedAt)
		if dbErr == nil {
			user = &u
		}
	}

	// Return validation result
	resp := map[string]interface{}{
		"client_name":   client.Name,
		"client_id":     client.ClientID,
		"description":   client.Description,
		"redirect_uri":  redirectURI,
		"scope":         scope,
		"response_type": responseType,
		"state":         state,
		"logged_in":     user != nil,
	}
	if user != nil {
		resp["user"] = user
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Approve handles POST /oauth/approve — generates auth code and returns redirect URL
func (h *OAuthFlowHandler) Approve(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	userID, err := h.getUserIDFromSession(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errs.NewAuthenticationError("Not logged in"))
		return
	}

	var req struct {
		ClientID    string `json:"client_id"`
		RedirectURI string `json:"redirect_uri"`
		Scope       string `json:"scope"`
		State       string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	// Re-validate client + redirect_uri
	var client models.OAuthClient
	err = h.db.QueryRow(`
		SELECT id, client_id, redirect_uris, scopes, is_active
		FROM oauth_clients WHERE client_id = ?`, req.ClientID).Scan(
		&client.ID, &client.ClientID, &client.RedirectURIs, &client.Scopes, &client.IsActive,
	)
	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Unknown client_id"))
		return
	}
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}
	if !client.IsActive {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Client deactivated"))
		return
	}

	var registeredURIs []string
	json.Unmarshal([]byte(client.RedirectURIs), &registeredURIs)
	matched := false
	for _, uri := range registeredURIs {
		if uri == req.RedirectURI {
			matched = true
			break
		}
	}
	if !matched {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("redirect_uri mismatch"))
		return
	}

	// Generate authorization code
	code, err := generateCode(32)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to generate authorization code"))
		return
	}

	// Store the code in Redis with metadata
	codeData := map[string]interface{}{
		"client_id":    req.ClientID,
		"user_id":      userID,
		"redirect_uri": req.RedirectURI,
		"scope":        req.Scope,
	}
	codeJSON, _ := json.Marshal(codeData)
	if err := h.cache.Set(authCodeKeyPrefix+code, string(codeJSON), authCodeTTL); err != nil {
		logger.Error("Failed to store auth code", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to create authorization code"))
		return
	}

	logger.Info("Authorization code issued",
		zap.String("client_id", req.ClientID), zap.Int("user_id", userID))

	// Build redirect URL
	redirectURL := req.RedirectURI + "?code=" + code
	if req.State != "" {
		redirectURL += "&state=" + req.State
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"redirect_url": redirectURL,
		"code":         code,
	})
}

// Authorize handles POST /oauth/authorize — exchanges auth code for access + refresh tokens
func (h *OAuthFlowHandler) Authorize(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		GrantType    string `json:"grant_type"`
		Code         string `json:"code"`
		RedirectURI  string `json:"redirect_uri"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
		return
	}

	if req.GrantType != "authorization_code" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("grant_type must be authorization_code"))
		return
	}
	if req.Code == "" || req.ClientID == "" || req.ClientSecret == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("code, client_id, and client_secret are required"))
		return
	}

	// Verify client credentials
	var storedSecret string
	var clientDBID int
	err := h.db.QueryRow(
		"SELECT id, client_secret FROM oauth_clients WHERE client_id = ? AND is_active = 1",
		req.ClientID,
	).Scan(&clientDBID, &storedSecret)
	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errs.NewAuthenticationError("Invalid client credentials"))
		return
	}
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Database error"))
		return
	}
	if storedSecret != req.ClientSecret {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errs.NewAuthenticationError("Invalid client credentials"))
		return
	}

	// Look up the authorization code in Redis
	raw, err := h.cache.Get(authCodeKeyPrefix + req.Code)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("Invalid or expired authorization code"))
		return
	}

	// Delete the code immediately (one-time use)
	h.cache.Delete(authCodeKeyPrefix + req.Code)

	var codeData map[string]interface{}
	switch v := raw.(type) {
	case string:
		json.Unmarshal([]byte(v), &codeData)
	case map[string]interface{}:
		codeData = v
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Invalid code data"))
		return
	}

	// Verify client_id matches the code
	if codeData["client_id"] != req.ClientID {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("client_id does not match the authorization code"))
		return
	}

	// Verify redirect_uri if provided
	if req.RedirectURI != "" && codeData["redirect_uri"] != req.RedirectURI {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs.NewValidationError("redirect_uri does not match"))
		return
	}

	// Extract user_id
	var userID int
	switch uid := codeData["user_id"].(type) {
	case float64:
		userID = int(uid)
	case int:
		userID = uid
	}

	scope, _ := codeData["scope"].(string)

	// Generate access token and refresh token
	accessToken, err := generateCode(32)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to generate tokens"))
		return
	}
	refreshToken, err := generateCode(32)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Failed to generate tokens"))
		return
	}

	// Store access token in Redis
	atData, _ := json.Marshal(map[string]interface{}{
		"user_id":   userID,
		"client_id": req.ClientID,
		"scope":     scope,
	})
	h.cache.Set(accessTokenKeyPrefix+accessToken, string(atData), accessTokenTTL)

	// Store refresh token in Redis
	rtData, _ := json.Marshal(map[string]interface{}{
		"user_id":   userID,
		"client_id": req.ClientID,
		"scope":     scope,
	})
	h.cache.Set(refreshTokenKeyPrefix+refreshToken, string(rtData), refreshTokenTTL)

	logger.Info("Tokens issued",
		zap.String("client_id", req.ClientID), zap.Int("user_id", userID))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": refreshToken,
		"scope":         scope,
	})
}

// DemoCallback handles GET /callback — a demo/test callback endpoint that
// receives the authorization code and exchanges it for tokens using hardcoded
// test client credentials. Renders the result as an HTML page.
func (h *OAuthFlowHandler) DemoCallback(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errParam := r.URL.Query().Get("error")
	errDesc := r.URL.Query().Get("error_description")

	// If the user denied consent, show that
	if errParam != "" {
		h.renderCallbackPage(w, false, map[string]interface{}{
			"error":             errParam,
			"error_description": errDesc,
			"state":             state,
		})
		return
	}

	if code == "" {
		h.renderCallbackPage(w, false, map[string]interface{}{
			"error":             "missing_code",
			"error_description": "No authorization code received.",
		})
		return
	}

	// Hardcoded demo client credentials
	const demoClientID = "f43bf29c0528932f6732bd59d0582dfd"
	const demoClientSecret = "f1865d713ca1dbfc18371a6b39e2a67d6639c1ebcfae38e399203ad076fa6077"
	const demoRedirectURI = "http://localhost:8080/callback"

	// Build the token exchange request
	tokenReqBody, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  demoRedirectURI,
		"client_id":     demoClientID,
		"client_secret": demoClientSecret,
	})

	// Call the /oauth/authorize endpoint internally
	tokenResp, err := http.Post(
		"http://localhost:8080/oauth/authorize",
		"application/json",
		bytes.NewReader(tokenReqBody),
	)
	if err != nil {
		logger.Error("Demo callback: failed to call /oauth/authorize", zap.Error(err))
		h.renderCallbackPage(w, false, map[string]interface{}{
			"error":             "token_exchange_failed",
			"error_description": fmt.Sprintf("Failed to reach token endpoint: %v", err),
		})
		return
	}
	defer tokenResp.Body.Close()

	respBody, _ := io.ReadAll(tokenResp.Body)

	var tokenData map[string]interface{}
	json.Unmarshal(respBody, &tokenData)

	if tokenResp.StatusCode != http.StatusOK {
		// Pass through the error from the authorize endpoint
		errMsg, _ := tokenData["Message"].(string)
		if errMsg == "" {
			errMsg = string(respBody)
		}
		h.renderCallbackPage(w, false, map[string]interface{}{
			"error":             "token_exchange_failed",
			"error_description": errMsg,
			"code":              code,
			"state":             state,
			"status_code":       tokenResp.StatusCode,
		})
		return
	}

	// Success — add the original code and state for display
	tokenData["code"] = code
	if state != "" {
		tokenData["state"] = state
	}
	h.renderCallbackPage(w, true, tokenData)
}

// renderCallbackPage renders a styled HTML page showing the callback result
func (h *OAuthFlowHandler) renderCallbackPage(w http.ResponseWriter, success bool, data map[string]interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	prettyJSON, _ := json.MarshalIndent(data, "", "  ")

	statusIcon := "✅"
	statusTitle := "Authorization Successful"
	statusColor := "#059669"
	statusBg := "#d1fae5"
	statusBorder := "#6ee7b7"
	if !success {
		statusIcon = "❌"
		statusTitle = "Authorization Failed"
		statusColor = "#991b1b"
		statusBg = "#fee2e2"
		statusBorder = "#fca5a5"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Callback - %s</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
            background: #f0f2f5;
            color: #1a1a2e;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            padding: 40px 16px;
        }
        .container { width: 100%%; max-width: 560px; }
        h1 { text-align: center; margin-bottom: 24px; font-size: 28px; color: #16213e; }
        .card {
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.08);
            padding: 32px;
            margin-bottom: 20px;
        }
        .status-banner {
            background: %s;
            border: 1px solid %s;
            color: %s;
            padding: 16px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 24px;
            font-size: 18px;
            font-weight: 600;
        }
        .token-block {
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 14px;
            word-break: break-all;
        }
        .token-block label {
            display: block;
            font-size: 11px;
            color: #888;
            font-weight: 700;
            text-transform: uppercase;
            margin-bottom: 4px;
            letter-spacing: 0.5px;
        }
        .token-block .val {
            font-family: 'Courier New', Courier, monospace;
            font-size: 14px;
            color: #111;
        }
        pre {
            background: #1e1e2e;
            color: #cdd6f4;
            padding: 20px;
            border-radius: 10px;
            font-size: 13px;
            overflow-x: auto;
            line-height: 1.5;
        }
        .section-title {
            font-size: 14px;
            font-weight: 600;
            color: #666;
            margin-bottom: 10px;
            margin-top: 20px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .back-link {
            display: block;
            text-align: center;
            margin-top: 16px;
            color: #0f3460;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 OAuth Callback</h1>
        <div class="card">
            <div class="status-banner">%s %s</div>`,
		statusTitle,
		statusBg, statusBorder, statusColor,
		statusIcon, statusTitle,
	)

	if success {
		accessToken, _ := data["access_token"].(string)
		refreshToken, _ := data["refresh_token"].(string)
		tokenType, _ := data["token_type"].(string)
		scope, _ := data["scope"].(string)
		expiresIn := ""
		if v, ok := data["expires_in"]; ok {
			expiresIn = fmt.Sprintf("%v", v)
		}
		code, _ := data["code"].(string)

		html += fmt.Sprintf(`
            <div class="token-block">
                <label>Authorization Code (used)</label>
                <div class="val">%s</div>
            </div>
            <div class="token-block">
                <label>Access Token</label>
                <div class="val">%s</div>
            </div>
            <div class="token-block">
                <label>Refresh Token</label>
                <div class="val">%s</div>
            </div>
            <div class="token-block">
                <label>Token Type</label>
                <div class="val">%s</div>
            </div>
            <div class="token-block">
                <label>Expires In</label>
                <div class="val">%s seconds</div>
            </div>
            <div class="token-block">
                <label>Scope</label>
                <div class="val">%s</div>
            </div>`,
			code, accessToken, refreshToken, tokenType, expiresIn, scope,
		)
	}

	html += fmt.Sprintf(`
            <p class="section-title">Full Response</p>
            <pre>%s</pre>
        </div>
        <a class="back-link" href="/">← Back to Dashboard</a>
    </div>
</body>
</html>`, string(prettyJSON))

	w.Write([]byte(html))
}
