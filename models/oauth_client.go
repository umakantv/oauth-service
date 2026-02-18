package models

import "time"

// OAuthClient represents an OAuth client in the system
// Used for registering clients that will use this OAuth server
type OAuthClient struct {
	ID           int       `json:"id" db:"id"`
	ClientID     string    `json:"client_id" db:"client_id"`
	ClientSecret string    `json:"client_secret" db:"client_secret"`
	Name         string    `json:"name" db:"name"`
	Email        string    `json:"email" db:"email"`
	RedirectURIs string    `json:"redirect_uris" db:"redirect_uris"` // Comma-separated allowed callback URLs
	Scopes       string    `json:"scopes" db:"scopes"`
	GrantTypes   string    `json:"grant_types" db:"grant_types"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// CreateOAuthClientRequest represents the request to register a new OAuth client
type CreateOAuthClientRequest struct {
	Name         string `json:"name"`
	Email        string `json:"email,omitempty"`
	RedirectURIs string `json:"redirect_uris"` // Required: e.g., "http://localhost:3000/callback,https://app.example.com/callback"
	Scopes       string `json:"scopes,omitempty"` // Default: openid,profile,email
	GrantTypes   string `json:"grant_types,omitempty"` // Default: authorization_code,refresh_token
}

// UpdateOAuthClientRequest represents the request to update an OAuth client
type UpdateOAuthClientRequest struct {
	Name         string `json:"name,omitempty"`
	Email        string `json:"email,omitempty"`
	RedirectURIs string `json:"redirect_uris,omitempty"`
	Scopes       string `json:"scopes,omitempty"`
	GrantTypes   string `json:"grant_types,omitempty"`
}

// Note: In production, client_secret should be hashed, not stored plain.
// For this simple OAuth server, we store it plainly for demo purposes.
// Also, typically generate client_id and client_secret server-side.
