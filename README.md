# OAuth Service

A complete example of a REST API service demonstrating all the go-utils packages, now implementing a simple OAuth server.

## Features

- **Database**: SQLite with local file storage (users and oauth_client tables)
- **HTTP Server**: Standardized routing with authentication
- **Cache**: In-memory caching for performance
- **Logger**: Structured logging with custom format
- **Errors**: Standardized error responses
- **OAuth Client Management**: APIs for registering OAuth clients with configurations like allowed callback URLs (redirect_uris), scopes, grant types, etc.

## Database

### Tables

- `users`: For user management (use /users APIs to add users as mentioned)
- `oauth_client`: For OAuth client configurations including:
  - client_id, client_secret (auto-generated on registration)
  - name, email
  - redirect_uris: Comma-separated allowed callback URLs (critical for security)
  - scopes: Comma-separated (default: openid,profile,email)
  - grant_types: (default: authorization_code,refresh_token)
- Indexes on email and client_id for performance

### Creating migrations

```bash
go run main.go --command create-migration --name your_migration --dir database/migrations
```

Migrations are automatically run on startup.



## API Endpoints

### Public/Unauthenticated Endpoints (for browser/UI and OAuth flows)
- `GET /health` - Health check
- `GET /` - Browser UI (static/index.html) for E2E testing all flows
- `POST /signup` - Create user + auto session (cookie-based)
- `POST /login` - Login with email/password (sets httpOnly cookie session in Redis)
- `GET /me` - Get current user from session cookie
- `GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=...` - OAuth confirmation page **(standard)**
  - Validates session (error "User is not logged in" if none), client_id, redirect_uri match
  - Shows approve page for logged-in user; generates code in Redis (TTL)
- `POST /oauth/authorize/approve` - Internal approve (code issuance + redirect)
- `POST /oauth/token` - Exchange auth code for access/refresh tokens **(standard OAuth endpoint)**
  - Validates client, code, redirect_uri (from client config)
  - grant_type=authorization_code
  - Response: {access_token, token_type: "bearer", expires_in, refresh_token, scope}

### Protected Endpoints (Bearer token required - admin)
**User Management** (pw now mandatory; for auth flows):
- `GET /users` - List all users
- `GET /users/{id}` - Get user by ID
- `POST /users` - Create new user **(updated)**
  - Requires: name, email, password (hashed with bcrypt)
- `PUT /users/{id}` - Update user **(updated)**
  - Optional password (re-hashed)
- `DELETE /users/{id}` - Delete user

**OAuth Client Management** (register clients with configs):
- `GET /oauth/clients` - List all OAuth clients
- `GET /oauth/clients/{id}` - Get OAuth client by ID
- `POST /oauth/clients` - Register (create) new OAuth client **(main)**
  - Auto-generates client_id/secret
  - Requires: name, redirect_uris (comma-sep allowed callbacks)
  - Optional: email, scopes, grant_types
- `PUT /oauth/clients/{id}` - Update (e.g., callbacks)
- `DELETE /oauth/clients/{id}` - Delete

## Authentication & Sessions

- **Admin APIs** (/users*, /oauth/clients*): Bearer `secret-token`
- **User Auth Flows** (/signup, /login, /me): Cookie-based (`session_id`, httpOnly); sessions in Redis (persistent)
- **OAuth Token** (/oauth/token): Client creds + code (uses client config for validation)
- Redis config in cache/initialize.go for sessions.

See static/index.html for browser testing.

## Request/Response Examples

### Create User (updated - password mandatory)
```bash
curl -X POST http://localhost:8080/users \
  -H "Authorization: Bearer secret-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com", "password": "securepass123"}'
```

### Signup / Login (/me) - Cookie Sessions (Redis)
```bash
# Signup
curl -X POST http://localhost:8080/signup \
  -H "Content-Type: application/json" \
  -d '{"name": "John", "email": "john@example.com", "password": "pass123"}' \
  -c cookies.txt

# Login (sets session cookie)
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email": "john@example.com", "password": "pass123"}' \
  -c cookies.txt

# /me (from Redis session)
curl -X GET http://localhost:8080/me -b cookies.txt
```

### OAuth Authorize (Confirmation Page - Browser Flow)
```
# After login + client reg (use client_id/redirect from reg)
# Open in browser (or):
curl -X GET "http://localhost:8080/oauth/authorize?response_type=code&client_id=client_ea34f7d4402c90adb8ccd3b4&redirect_uri=http://localhost:3001/cb&scope=openid" \
  -b cookies.txt  # From login session (sample .env client)
```
- If logged in: Shows approve page.
- Approve: Gen code in Redis (TTL), redirect to /cb?code=...
- No login: "User is not logged in" error.

### /cb and /oauth/callback (Complete Flow , Server-Side Exchange)
- Redirect lands on /cb?code=... (sample redirect_uri from .env)
- /oauth/callback?code=...&client_id=... : Server-only exchange (hides secret) , logs success , shows UI success.

### /oauth/token (Auth Code Exchange)
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "your_code_from_authorize",
    "redirect_uri": "http://localhost:3001/cb",
    "client_id": "client_ea34f7d4402c90adb8ccd3b4",
    "client_secret": "e86948d7bf7c005ecebf28c6bde0b172c064b084d30b23f6b322ddfa063c99e8"
  }'
```
Response: Standard {access_token, ...} 

### Register OAuth Client
```bash
curl -X POST http://localhost:8080/oauth/clients \
  -H "Authorization: Bearer secret-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "App", "redirect_uris": "http://localhost:3001/cb"}'
```

Browser UI at `/` for E2E (incl. OAuth start with sample .env client; /cb exchange hides secret).

See handlers/oauth_authorize.go for details (server-side callback).

## Running the Service

Run manually (do not auto-start):

1. Ensure Redis running on localhost:6379

2. Run migration for password: `go run main.go --command start` (manual stop)

3. `go run main.go` 

Browser UI at / for E2E (signup etc with cookies).

## Database

SQLite `./oauth_service.db` (run migrations manually):

- `users`: id, name, email, password (hashed, mandatory), timestamps
- `oauth_client`: client configs (redirect_uris etc.)
- `oauth_auth_codes`, `oauth_tokens`: For token flow
- Run user-added migration for pw field.

Cache: Redis for sessions.

## Logging

All requests are logged with the format:
```
2023-12-01 10:30:45 - GetUser - GET - /users/{id} - client:user-service-client - User retrieved successfully
```

## Caching

- User list cached for 5 minutes
- Individual users cached for 10 minutes
- Cache automatically cleared on create/update/delete operations

## Error Responses

Standardized error responses using the errs package:

```json
{
  "Code": 404,
  "Message": "User not found"
}
```

## Architecture

```
main.go          - Service entry point
handlers/        - Request handlers
models/          - Data models
db/              - Database schema
```

This example demonstrates enterprise-ready patterns for building microservices with the go-utils packages.