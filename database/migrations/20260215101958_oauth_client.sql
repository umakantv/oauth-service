-- Migration: oauth_client
-- Generated: 20260215101958 UTC

-- Create oauth_client table for OAuth 2.0 client registrations
CREATE TABLE IF NOT EXISTS oauth_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id VARCHAR(64) NOT NULL UNIQUE,
    client_secret VARCHAR(128) NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    redirect_uris TEXT NOT NULL DEFAULT '[]',        -- JSON array of allowed redirect URIs
    grant_types TEXT NOT NULL DEFAULT '["authorization_code"]', -- JSON array: authorization_code, client_credentials, refresh_token, implicit
    response_types TEXT NOT NULL DEFAULT '["code"]', -- JSON array: code, token
    scopes TEXT NOT NULL DEFAULT '',                  -- space-separated list of allowed scopes
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic', -- client_secret_basic, client_secret_post, none
    is_confidential INTEGER NOT NULL DEFAULT 1,      -- 1 = confidential client, 0 = public client
    is_active INTEGER NOT NULL DEFAULT 1,            -- 1 = active, 0 = revoked
    owner_id INTEGER,                                -- reference to users table (who registered the client)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_owner_id ON oauth_clients(owner_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_is_active ON oauth_clients(is_active);
