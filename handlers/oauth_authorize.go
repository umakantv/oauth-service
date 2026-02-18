package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"oauth-service/models"

	"github.com/jmoiron/sqlx"
	"github.com/umakantv/go-utils/cache"
	"github.com/umakantv/go-utils/httpserver"
	"go.uber.org/zap"
)

// OAuthAuthorizeHandler handles GET /oauth/authorize for OAuth initiation
// Shows confirmation page to logged-in user, validates standard params + client config
// Generates auth code on approval (stored in Redis with TTL for /token)
type OAuthAuthorizeHandler struct {
	db    *sqlx.DB
	cache cache.Cache
}

// NewOAuthAuthorizeHandler creates the handler
func NewOAuthAuthorizeHandler(db *sqlx.DB, cache cache.Cache) *OAuthAuthorizeHandler {
	return &OAuthAuthorizeHandler{
		db:    db,
		cache: cache,
	}
}

// HandleAuthorize handles the endpoint (httpserver compat)
// Standard query params: ?response_type=code&client_id=...&redirect_uri=...&scope=...
// If no session/user: error "User is not logged in"
// Validates client_id + redirect_uri match from oauth_client
// Shows confirm page; approve -> gen code in Redis (TTL 10m) + redirect to callback?code=...
func (h *OAuthAuthorizeHandler) HandleAuthorize(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	logRequest(ctx, "info", "OAuth authorize request")

	// Parse query params (standard OAuth)
	query := r.URL.Query()
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	scope := query.Get("scope")
	responseType := query.Get("response_type") // expect "code"

	if responseType != "code" || clientID == "" || redirectURI == "" {
		logRequest(ctx, "error", "Invalid authorize params")
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	// Check session cookie for logged-in user (reuse /me logic + Redis)
	cookie, err := r.Cookie("session_id")
	if err != nil {
		logRequest(ctx, "error", "No session - user not logged in")
		// Error page as specified
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<h1>Error: User is not logged in</h1><p><a href="/login">Login first</a></p>`))
		return
	}

	// Get user session from Redis
	cached, err := h.cache.Get(sessionKeyPrefix + cookie.Value)
	if err != nil {
		logRequest(ctx, "error", "Invalid/expired session")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sessionData := cached.(map[string]interface{})
	userID := int(sessionData["user_id"].(float64))
	userEmail := sessionData["email"].(string)

	// Validate client + redirect_uri vs registered config (security)
	var client models.OAuthClient
	err = h.db.QueryRow("SELECT client_id, redirect_uris, scopes FROM oauth_client WHERE client_id = ?", clientID).
		Scan(&client.ClientID, &client.RedirectURIs, &client.Scopes)
	if err == sql.ErrNoRows {
		logRequest(ctx, "error", "Invalid client_id", zap.String("client_id", clientID))
		http.Error(w, "invalid_client", http.StatusBadRequest)
		return
	}
	if err != nil {
		logRequest(ctx, "error", "Client lookup failed", zap.Error(err))
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	// Verify redirect_uri matches client's allowed callbacks (exact or contains for comma-sep)
	if !strings.Contains(client.RedirectURIs, redirectURI) {
		logRequest(ctx, "error", "Redirect mismatch", zap.String("provided", redirectURI), zap.String("allowed", client.RedirectURIs))
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	// (Scope check optional/simple for now)

	logRequest(ctx, "info", "Showing OAuth confirm page", zap.String("client_id", clientID), zap.String("user", userEmail))

	// Show confirmation page (HTML with approve button)
	// On approve: gen code, store in Redis with TTL, redirect to callback?code=...
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><title>OAuth Confirmation</title></head>
<body>
<h1>Authorize %s?</h1>
<p>User: %s</p>
<p>Client: %s</p>
<p>Redirect: %s</p>
<p>Scope: %s</p>
<form method="post" action="/oauth/authorize/approve?client_id=%s&redirect_uri=%s&scope=%s&user_id=%d">
<button type="submit">Approve</button>
</form>
</body>
</html>
`, clientID, userEmail, clientID, redirectURI, scope, clientID, url.QueryEscape(redirectURI), scope, userID)))
}

// HandleApprove (POST from confirm page) - gen auth code , store in Redis (TTL), redirect
// Code for /token exchange ; returns httpserver.HandlerFunc compat
// Uses Redis with TTL for expiry
func (h *OAuthAuthorizeHandler) HandleApprove() httpserver.HandlerFunc {
	return httpserver.HandlerFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		// Parse from form/query
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		scope := r.URL.Query().Get("scope")
		userIDStr := r.URL.Query().Get("user_id")
		userID, _ := strconv.Atoi(userIDStr)

		// Gen code , store in Redis key=code , value=map (no marshal) , TTL 10m for expiry
		// Reuse generateAuthCode ; Redis for persistent expiry
		code := generateAuthCode()
		codeData := map[string]interface{}{
			"code":         code,
			"client_id":    clientID,
			"user_id":      userID,
			"redirect_uri": redirectURI,
			"scopes":       scope,
		}
		h.cache.Set("oauth_code:"+code, codeData, 10*time.Minute) // Redis TTL expiry

		logRequest(ctx, "info", "Auth code issued", zap.String("code", code), zap.String("client_id", clientID))

		// Redirect to callback with code (standard)
		redirectURL, _ := url.Parse(redirectURI)
		q := redirectURL.Query()
		q.Add("code", code)
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	})
}

// HandleCallback handles GET /oauth/callback?code=...&client_id=... (server-side for client app sim)
// Hides client_secret (sample from .env), exchanges code at /token , logs success
// Returns to UI/browser ; completes flow without exposing secret
func (h *OAuthAuthorizeHandler) HandleCallback(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	logRequest(ctx, "info", "OAuth callback received (client sim)")

	// Parse query
	code := r.URL.Query().Get("code")
	clientID := r.URL.Query().Get("client_id")
	if code == "" || clientID == "" {
		logRequest(ctx, "error", "Missing code/client_id")
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	// Sample client config from .env (server-only , never in UI/browser)
	// redirect_uri matches registered
	sampleClientSecret := "e86948d7bf7c005ecebf28c6bde0b172c064b084d30b23f6b322ddfa063c99e8"
	redirectURI := "http://localhost:3001/cb"

	// Server-side exchange: POST to /oauth/token (using secret)
	tokenReq := models.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  redirectURI,
		ClientID:     clientID,
		ClientSecret: sampleClientSecret,
	}
	reqBody, _ := json.Marshal(tokenReq)
	tokenResp, err := http.Post("http://localhost:3001/oauth/token", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		logRequest(ctx, "error", "Token exchange failed", zap.Error(err))
		http.Error(w, "token_error", http.StatusInternalServerError)
		return
	}
	defer tokenResp.Body.Close()

	var token models.TokenResponse
	json.NewDecoder(tokenResp.Body).Decode(&token)

	// Log success on server (safe slice to avoid panic if token empty)
	accessTokenPreview := ""
	if len(token.AccessToken) > 10 {
		accessTokenPreview = token.AccessToken[:10] + "..."
	}
	logRequest(ctx, "info", "Token exchange successful", zap.String("access_token", accessTokenPreview), zap.String("client_id", clientID))

	// Success response to UI/browser
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf(`
<!DOCTYPE html>
<html><head><title>OAuth Success</title></head>
<body>
<h1>OAuth Flow Complete!</h1>
<p>Code exchanged successfully for token (see server logs).</p>
<p>Access Token: %s...</p>
<p><a href="/">Back to UI</a></p>
</body></html>
`, token.AccessToken[:20])))
}

// Note: Uses Redis for code (TTL for expiry); validates standard params + client config
// Confirmation page for logged-in user only; ties to session.
// generateAuthCode + sessionKeyPrefix reused from other handlers.
// /oauth/callback hides secret , does exchange , logs .