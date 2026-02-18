package models

import "time"

// AuthCode represents a temporary authorization code for OAuth code flow
// Stored in DB, validated during token exchange to prevent replay
type AuthCode struct {
	ID          int       `json:"id" db:"id"`
	Code        string    `json:"code" db:"code"`
	ClientID    string    `json:"client_id" db:"client_id"`
	UserID      *int      `json:"user_id,omitempty" db:"user_id"` // Optional link to users
	RedirectURI string    `json:"redirect_uri" db:"redirect_uri"`
	Scopes      string    `json:"scopes" db:"scopes"`
	ExpiresAt   time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// Token represents issued OAuth access/refresh tokens
// Simple opaque tokens for this implementation
type Token struct {
	ID           int       `json:"id" db:"id"`
	AccessToken  string    `json:"access_token" db:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty" db:"refresh_token"`
	ClientID     string    `json:"client_id" db:"client_id"`
	UserID       *int      `json:"user_id,omitempty" db:"user_id"`
	Scopes       string    `json:"scopes" db:"scopes"`
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// TokenRequest represents the POST /oauth/token request body
// Standard OAuth2 params for code exchange
type TokenRequest struct {
	GrantType    string `json:"grant_type"`    // e.g., "authorization_code"
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// TokenResponse is the standard OAuth2 response for /token
// Includes access_token, refresh_token, etc.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"` // "bearer"
	ExpiresIn    int    `json:"expires_in"` // seconds
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Note: For simplicity:
// - Auth codes expire in 10min, access tokens 1hr, refresh 7d
// - No PKCE/JWT signing (add later for prod)
// - Codes/tokens link to clients/users for validation
// - Simulate code issuance for tests (full /authorize next)
