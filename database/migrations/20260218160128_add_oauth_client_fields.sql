-- Migration: add_oauth_client_fields
-- Generated: 20260218160128 UTC
-- Updates oauth_client table for proper OAuth client configuration
-- Includes allowed callback URLs (redirect_uris), scopes, etc.
-- Also ensures users table exists

-- Ensure users table exists (for user management via /users APIs)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create index on email for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Drop existing oauth_client table (empty in dev, recreate with full OAuth config)
DROP TABLE IF EXISTS oauth_client;

-- Create oauth_client table with necessary OAuth configurations
-- redirect_uris: comma-separated list of allowed callback URLs
-- scopes: comma-separated allowed scopes
-- grant_types: supported grant types
CREATE TABLE IF NOT EXISTS oauth_client (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id VARCHAR(50) NOT NULL UNIQUE,
    client_secret VARCHAR(100) NOT NULL,
    name TEXT NOT NULL,
    email TEXT,  -- Optional contact email
    redirect_uris TEXT NOT NULL,  -- e.g., "http://localhost:3000/callback,https://app.example.com/callback"
    scopes TEXT DEFAULT 'openid,profile,email',
    grant_types TEXT DEFAULT 'authorization_code,refresh_token',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create index on client_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_oauth_client_client_id ON oauth_client(client_id);
