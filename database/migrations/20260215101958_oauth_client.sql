-- Migration: oauth_client
-- Generated: 20260215101958 UTC

-- Create users table
CREATE TABLE IF NOT EXISTS oauth_client (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
		client_id VARCHAR(50) NOT NULL,
		client_secret VARCHAR(50) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
