-- Migration: oauth_tokens
-- Generated: 20260218162904 UTC
-- Adds tables for simple OAuth flow: auth codes (for /authorize) and tokens
-- Supports code exchange at /token endpoint, validation against client configs
-- Note: For production, use proper JWT/signing, revocation, etc.

-- oauth_auth_codes: Temporary codes issued by /authorize (simulated for now)
-- Validated in /token for security (incl. redirect_uri, client_id match)
CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(50) NOT NULL UNIQUE,
    client_id VARCHAR(50) NOT NULL,
    user_id INTEGER,  -- Links to users table
    redirect_uri TEXT NOT NULL,
    scopes TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_client(client_id)
);

-- Index for fast code lookups
CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_code ON oauth_auth_codes(code);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_client ON oauth_auth_codes(client_id);

-- oauth_tokens: Issued access/refresh tokens
-- Simple opaque tokens stored for validation (e.g., /userinfo future)
CREATE TABLE IF NOT EXISTS oauth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    access_token VARCHAR(50) NOT NULL UNIQUE,
    refresh_token VARCHAR(50) UNIQUE,
    client_id VARCHAR(50) NOT NULL,
    user_id INTEGER,
    scopes TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_client(client_id)
);

-- Indexes for token validation/lookups
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_access ON oauth_tokens(access_token);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh ON oauth_tokens(refresh_token);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_client ON oauth_tokens(client_id);
