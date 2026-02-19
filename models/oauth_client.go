package models

import "time"

// OAuthClient represents a registered OAuth 2.0 client application
type OAuthClient struct {
	ID                      int       `json:"id" db:"id"`
	ClientID                string    `json:"client_id" db:"client_id"`
	ClientSecret            string    `json:"client_secret,omitempty" db:"client_secret"` // omitted in list responses
	Name                    string    `json:"name" db:"name"`
	Description             string    `json:"description" db:"description"`
	RedirectURIs            string    `json:"redirect_uris" db:"redirect_uris"`                         // stored as JSON array string
	GrantTypes              string    `json:"grant_types" db:"grant_types"`                              // stored as JSON array string
	ResponseTypes           string    `json:"response_types" db:"response_types"`                       // stored as JSON array string
	Scopes                  string    `json:"scopes" db:"scopes"`                                       // space-separated scopes
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method" db:"token_endpoint_auth_method"` // client_secret_basic, client_secret_post, none
	IsConfidential          bool      `json:"is_confidential" db:"is_confidential"`
	IsActive                bool      `json:"is_active" db:"is_active"`
	OwnerID                 *int      `json:"owner_id,omitempty" db:"owner_id"`
	CreatedAt               time.Time `json:"created_at" db:"created_at"`
	UpdatedAt               time.Time `json:"updated_at" db:"updated_at"`
}

// CreateOAuthClientRequest represents the request to register a new OAuth client
type CreateOAuthClientRequest struct {
	Name                    string   `json:"name"`
	Description             string   `json:"description,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`              // defaults to ["authorization_code"]
	ResponseTypes           []string `json:"response_types,omitempty"`           // defaults to ["code"]
	Scopes                  string   `json:"scopes,omitempty"`                   // space-separated scopes
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"` // defaults to "client_secret_basic"
	IsConfidential          *bool    `json:"is_confidential,omitempty"`           // defaults to true
	OwnerID                 *int     `json:"owner_id,omitempty"`
}

// UpdateOAuthClientRequest represents the request to update an OAuth client
type UpdateOAuthClientRequest struct {
	Name                    string   `json:"name,omitempty"`
	Description             string   `json:"description,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scopes                  string   `json:"scopes,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	IsConfidential          *bool    `json:"is_confidential,omitempty"`
	IsActive                *bool    `json:"is_active,omitempty"`
}

// OAuthClientResponse is the response returned when creating a client (includes secret)
type OAuthClientResponse struct {
	OAuthClient
	ClientSecret string `json:"client_secret"` // shown only on creation
}

// Allowed values for validation
var (
	AllowedGrantTypes              = map[string]bool{"authorization_code": true, "client_credentials": true, "refresh_token": true, "implicit": true}
	AllowedResponseTypes           = map[string]bool{"code": true, "token": true}
	AllowedTokenEndpointAuthMethods = map[string]bool{"client_secret_basic": true, "client_secret_post": true, "none": true}
)
