package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"oauth-service/models"

	"github.com/jmoiron/sqlx"
	"github.com/umakantv/go-utils/cache"
	"github.com/umakantv/go-utils/errs"
	"go.uber.org/zap"
)

// OAuthTokenHandler handles OAuth token endpoints for the simple OAuth server
// Implements /oauth/token for code exchange to access/refresh tokens
// Validates against registered client configs (e.g., redirect_uris, secrets)
type OAuthTokenHandler struct {
	db    *sqlx.DB
	cache cache.Cache
}

// NewOAuthTokenHandler creates a new token handler
func NewOAuthTokenHandler(db *sqlx.DB, cache cache.Cache) *OAuthTokenHandler {
	return &OAuthTokenHandler{
		db:    db,
		cache: cache,
	}
}

// generateAuthCode generates temp auth code (for sim /authorize)
func generateAuthCode() string {
	// Reuse rand logic similar to client_id
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "code_" + time.Now().Format("20060102150405")
	}
	return "code_" + hex.EncodeToString(b)[:32]
}

// generateAccessToken generates opaque access token
func generateAccessToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "at_" + time.Now().Format("20060102150405")
	}
	return "at_" + hex.EncodeToString(b)
}

// generateRefreshToken generates opaque refresh token
func generateRefreshToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "rt_" + time.Now().Format("20060102150405")
	}
	return "rt_" + hex.EncodeToString(b)
}

// CreateAuthCodeForTest is a helper to simulate issuing an auth code
// (e.g., after /authorize; inserts to DB for /token exchange test)
// Returns code for client
func (h *OAuthTokenHandler) CreateAuthCodeForTest(clientID, redirectURI, scopes string, userID *int) (string, error) {
	code := generateAuthCode()
	expiresAt := time.Now().Add(10 * time.Minute) // Short-lived

	_, err := h.db.Exec("INSERT INTO oauth_auth_codes (code, client_id, user_id, redirect_uri, scopes, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		code, clientID, userID, redirectURI, scopes, expiresAt, time.Now())
	if err != nil {
		return "", err
	}
	return code, nil
}

// HandleToken handles POST /oauth/token
// Standard endpoint for exchanging auth code for tokens
// Validates: client creds, code validity, redirect_uri match (from client config)
func (h *OAuthTokenHandler) HandleToken(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	// Log using shared func
	logRequest(ctx, "info", "Token request")

	// Parse request (support JSON or form for OAuth compat)
	var req models.TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Fallback to form if JSON fails (common for OAuth clients)
		if err := r.ParseForm(); err == nil {
			req.GrantType = r.Form.Get("grant_type")
			req.Code = r.Form.Get("code")
			req.RedirectURI = r.Form.Get("redirect_uri")
			req.ClientID = r.Form.Get("client_id")
			req.ClientSecret = r.Form.Get("client_secret")
		} else {
			logRequest(ctx, "error", "Invalid token request", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errs.NewValidationError("Invalid request"))
			return
		}
	}

	// Validate grant_type (only auth code for simple impl)
	if req.GrantType != "authorization_code" {
		logRequest(ctx, "error", "Unsupported grant_type", zap.String("grant_type", req.GrantType))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
		return
	}

	// Required params
	if req.Code == "" || req.ClientID == "" || req.ClientSecret == "" || req.RedirectURI == "" {
		logRequest(ctx, "error", "Missing required token params")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
		return
	}

	// 1. Validate client exists and secret matches (from oauth_client config)
	var client models.OAuthClient
	err := h.db.QueryRow("SELECT client_id, client_secret, redirect_uris FROM oauth_client WHERE client_id = ?", req.ClientID).
		Scan(&client.ClientID, &client.ClientSecret, &client.RedirectURIs)
	if err == sql.ErrNoRows || client.ClientSecret != req.ClientSecret {
		logRequest(ctx, "error", "Invalid client credentials", zap.String("client_id", req.ClientID))
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		return
	}
	if err != nil {
		logRequest(ctx, "error", "Client lookup failed", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Server error"))
		return
	}

	// 2. Validate redirect_uri matches client's allowed callbacks (security)
	// Simple check: contains (for comma sep list)
	if !strings.Contains(client.RedirectURIs, req.RedirectURI) {
		logRequest(ctx, "error", "Redirect URI mismatch", zap.String("provided", req.RedirectURI), zap.String("allowed", client.RedirectURIs))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}

	// 3. Validate auth code: exists, not expired, matches client/redirect
	// Use Redis "oauth_code:..." (TTL expiry from authorize flow , per spec; fallback DB if needed)
	// Avoids schema CLI ; cache.Get returns interface{} map
	cachedCode, err := h.cache.Get("oauth_code:" + req.Code)
	if err != nil {
		logRequest(ctx, "error", "Invalid or expired auth code", zap.String("code", req.Code))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	codeData, ok := cachedCode.(map[string]interface{})
	if !ok {
		logRequest(ctx, "error", "Invalid code data type in cache", zap.String("code", req.Code))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Server error"))
		return
	}
	// Check match (client , redirect)
	if codeData["client_id"] != req.ClientID || codeData["redirect_uri"] != req.RedirectURI {
		logRequest(ctx, "error", "Code mismatch", zap.String("code", req.Code))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	// Extract scopes from code data
	authScopes := codeData["scopes"].(string)

	// 4. Issue new tokens (store in oauth_tokens DB)
	accessToken := generateAccessToken()
	refreshToken := generateRefreshToken()
	expiresAt := time.Now().Add(1 * time.Hour) // Access token lifetime
	_, err = h.db.Exec(`
		INSERT INTO oauth_tokens (access_token, refresh_token, client_id, user_id, scopes, expires_at, created_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, accessToken, refreshToken, req.ClientID, nil, authScopes, expiresAt, time.Now()) // user_id nil for sim
	if err != nil {
		logRequest(ctx, "error", "Failed to store token", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errs.NewInternalServerError("Token issuance failed"))
		return
	}

	// 5. Cleanup used code (one-time use from Redis)
	h.cache.Delete("oauth_code:" + req.Code)

	// Clear any caches if added later
	// h.cache.Delete(...)

	logRequest(ctx, "info", "Tokens issued successfully", zap.String("client_id", req.ClientID))

	// Standard OAuth2 response
	resp := models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		ExpiresIn:    3600, // 1hr
		RefreshToken: refreshToken,
		Scope:        authScopes,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
