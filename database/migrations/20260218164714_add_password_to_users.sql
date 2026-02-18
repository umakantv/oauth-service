-- Migration: add_password_to_users
-- Generated: 20260218164714 UTC
-- Adds password field to users table for auth flows
-- Passwords will be hashed (bcrypt) in app layer; mandatory for /signup/login
-- Run this migration manually via server start (as per instructions)

-- Add password column (hashed, required for auth)
ALTER TABLE users ADD COLUMN password TEXT NOT NULL DEFAULT '';

-- Note: Default empty for existing rows; update via /signup or manual
-- In prod, enforce no defaults and migrate data
-- Index not needed for password (not queried directly)
