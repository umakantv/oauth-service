# OAuth Service

A microservice implementing OAuth 2.0 client management with user authentication, built on [go-utils](https://github.com/umakantv/go-utils).

## Features

- **Database**: SQLite with local file storage and auto-migrations
- **HTTP Server**: Standardized routing with bearer-token and cookie-based auth
- **Cache / Sessions**: Redis (`localhost:6379`) for caching and session storage
- **Auth UI**: Static login/signup page at `http://localhost:8080/`
- **Logger**: Structured logging with custom format
- **Errors**: Standardized error responses

## Prerequisites

- Go 1.19+
- Redis running on `localhost:6379`

## Running the Service

```bash
# Start Redis (if not already running)
redis-server &

# Run the service
go run main.go

# Open the UI
open http://localhost:8080/
```

## Database

### Creating migrations

```bash
go run main.go --command create-migration --name my_migration --dir database/migrations
```

## API Endpoints

### Public Endpoints (no auth required)

| Method | Path      | Description                                  |
|--------|-----------|----------------------------------------------|
| `GET`  | `/`       | Static login/signup UI                       |
| `GET`  | `/health` | Health check                                 |
| `POST` | `/signup` | Register a new user (cookie-based session)   |
| `POST` | `/login`  | Login with email & password (sets session cookie) |
| `GET`  | `/me`     | Get current user from session cookie         |
| `POST` | `/logout` | Destroy session and clear cookie             |

### Protected Endpoints (Bearer token required)

#### Users
| Method   | Path           | Description      |
|----------|----------------|------------------|
| `GET`    | `/users`       | List all users   |
| `GET`    | `/users/{id}`  | Get user by ID   |
| `POST`   | `/users`       | Create new user (requires `name`, `email`, `password`) |
| `PUT`    | `/users/{id}`  | Update user (optional `password`)     |
| `DELETE` | `/users/{id}`  | Delete user      |

#### OAuth Clients
| Method   | Path                                 | Description                    |
|----------|--------------------------------------|--------------------------------|
| `POST`   | `/oauth/clients`                     | Register a new OAuth client    |
| `GET`    | `/oauth/clients`                     | List all OAuth clients         |
| `GET`    | `/oauth/clients/{id}`                | Get OAuth client by ID         |
| `PUT`    | `/oauth/clients/{id}`                | Update OAuth client config     |
| `DELETE` | `/oauth/clients/{id}`                | Delete (deregister) client     |
| `POST`   | `/oauth/clients/{id}/rotate-secret`  | Rotate client secret           |

### Cookie-based Endpoints (session auth)

#### OAuth Flow
| Method | Path                       | Description                                        |
|--------|----------------------------|----------------------------------------------------|
| `POST` | `/oauth/register-client`   | Register OAuth client (owner_id from session)      |
| `GET`  | `/oauth/initialize`        | Start OAuth flow (serves consent/login UI)         |
| `GET`  | `/oauth/validate-init`     | Validate OAuth params, return client info + user   |
| `POST` | `/oauth/approve`           | Approve consent, generate auth code, return redirect |
| `POST` | `/oauth/authorize`         | Exchange auth code for access + refresh tokens     |

## Authentication

### Bearer Token (Admin / API access)

All `/users` and `/oauth/clients` endpoints require:

```
Authorization: Bearer secret-token
```

### Cookie-based Sessions (UI)

`/signup` and `/login` set an `HttpOnly` session cookie (`session_token`).
The session is stored in Redis with a 24-hour TTL.
`/me` reads the cookie and returns the logged-in user.

## OAuth 2.0 Authorization Code Flow

This service implements a full OAuth 2.0 Authorization Code flow. Here's the end-to-end process:

### Flow Overview

```
┌──────────┐     1. GET /oauth/initialize        ┌──────────────┐
│  Client   │ ──────────────────────────────────► │ OAuth Service │
│  App      │     ?client_id=...&redirect_uri=... │  (this app)   │
└──────────┘                                      └──────┬───────┘
                                                         │
                                                    2. Shows login
                                                       or consent
                                                         │
                                                    3. User approves
                                                         │
┌──────────┐     4. Redirect to callback          ┌──────┴───────┐
│  Client   │ ◄────────────────────────────────── │ OAuth Service │
│  App      │     ?code=AUTH_CODE&state=...        └──────────────┘
└─────┬────┘
      │
      │          5. POST /oauth/authorize
      │             {code, client_id, client_secret}
      │                                           ┌──────────────┐
      └──────────────────────────────────────────►│ OAuth Service │
                                                  │               │
               6. Returns access_token +          │               │
                  refresh_token                   └──────────────┘
```

### Step-by-Step

#### 1. Register an OAuth Client (from the UI)

Log in at `http://localhost:8080/` and use the **Register OAuth Client** form to create a new client.
You'll receive a `client_id` and `client_secret`. Save the secret — it's shown only once.

Alternatively, register via API:
```bash
curl -X POST http://localhost:8080/oauth/register-client \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Web App",
    "description": "A web application",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "scopes": "openid profile email"
  }'
```

#### 2. Initialize the OAuth Flow

Redirect the user's browser to:
```
http://localhost:8080/oauth/initialize?client_id=CLIENT_ID&redirect_uri=https://myapp.example.com/callback&scope=openid+profile+email&response_type=code&state=RANDOM_STATE
```

| Parameter      | Required | Description                                    |
|----------------|----------|------------------------------------------------|
| `client_id`    | Yes      | The client ID from registration                |
| `redirect_uri` | Yes      | Must match one of the registered redirect URIs |
| `scope`        | No       | Space-separated scopes (default: `openid`)     |
| `response_type`| No       | Must be `code` (default)                       |
| `state`        | No       | CSRF protection string, returned in callback   |

**Behavior:**
- If the user is **not logged in** → shows a login/signup form
- If the user **is logged in** → shows a consent screen with the app name, scopes, and redirect URI
- If `client_id` is invalid or `redirect_uri` doesn't match → shows an error

#### 3. User Approves (or Denies)

- **Approve**: The user is redirected to the `redirect_uri` with an authorization code:
  ```
  https://myapp.example.com/callback?code=AUTH_CODE&state=RANDOM_STATE
  ```
- **Deny**: The user is redirected with an error:
  ```
  https://myapp.example.com/callback?error=access_denied&error_description=The+user+denied+the+request&state=RANDOM_STATE
  ```

#### 4. Exchange Authorization Code for Tokens

The client app's backend exchanges the code for tokens:
```bash
curl -X POST http://localhost:8080/oauth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "AUTH_CODE_FROM_CALLBACK",
    "redirect_uri": "https://myapp.example.com/callback",
    "client_id": "CLIENT_ID",
    "client_secret": "CLIENT_SECRET"
  }'
```

**Response** (200 OK):
```json
{
  "access_token": "64-char-hex-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "64-char-hex-token",
  "scope": "openid profile email"
}
```

**Notes:**
- Authorization codes are single-use and expire after 10 minutes
- Access tokens expire after 1 hour
- Refresh tokens expire after 30 days
- All tokens are stored in Redis

## Request/Response Examples

### Signup (cookie-based)
```bash
curl -X POST http://localhost:8080/signup \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"name": "John Doe", "email": "john@example.com", "password": "secret123"}'
```

### Login (cookie-based)
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email": "john@example.com", "password": "secret123"}'
```

### Get Current User (/me)
```bash
curl -X GET http://localhost:8080/me \
  -b cookies.txt
```

### Logout
```bash
curl -X POST http://localhost:8080/logout \
  -b cookies.txt -c cookies.txt
```

### Create User (API)
```bash
curl -X POST http://localhost:8080/users \
  -H "Authorization: Bearer secret-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com", "password": "secret123"}'
```

### Get Users
```bash
curl -X GET http://localhost:8080/users \
  -H "Authorization: Bearer secret-token"
```

### Get User by ID
```bash
curl -X GET http://localhost:8080/users/1 \
  -H "Authorization: Bearer secret-token"
```

### Update User
```bash
curl -X PUT http://localhost:8080/users/1 \
  -H "Authorization: Bearer secret-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "Jane Doe", "email": "jane@example.com", "password": "newpassword"}'
```

### Delete User
```bash
curl -X DELETE http://localhost:8080/users/1 \
  -H "Authorization: Bearer secret-token"
```

### Register an OAuth Client (API)
```bash
curl -X POST http://localhost:8080/oauth/clients \
  -H "Authorization: Bearer secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Web App",
    "description": "A web application that needs OAuth access",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scopes": "openid profile email",
    "token_endpoint_auth_method": "client_secret_basic",
    "is_confidential": true,
    "owner_id": 1
  }'
```

**Response** (201 Created) — `client_secret` is only shown on registration:
```json
{
  "id": 1,
  "client_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "client_secret": "s3cr3t...64hexchars...",
  "name": "My Web App",
  "redirect_uris": "[\"https://myapp.example.com/callback\"]",
  "grant_types": "[\"authorization_code\",\"refresh_token\"]",
  "scopes": "openid profile email",
  "is_confidential": true,
  "is_active": true,
  "owner_id": 1
}
```

### List OAuth Clients
```bash
curl -X GET http://localhost:8080/oauth/clients \
  -H "Authorization: Bearer secret-token"
```

### Get OAuth Client by ID
```bash
curl -X GET http://localhost:8080/oauth/clients/1 \
  -H "Authorization: Bearer secret-token"
```

### Update OAuth Client
```bash
curl -X PUT http://localhost:8080/oauth/clients/1 \
  -H "Authorization: Bearer secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://myapp.example.com/callback", "https://myapp.example.com/v2/callback"],
    "scopes": "openid profile email offline_access"
  }'
```

### Delete OAuth Client
```bash
curl -X DELETE http://localhost:8080/oauth/clients/1 \
  -H "Authorization: Bearer secret-token"
```

### Rotate Client Secret
```bash
curl -X POST http://localhost:8080/oauth/clients/1/rotate-secret \
  -H "Authorization: Bearer secret-token"
```

**Response:**
```json
{
  "client_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "client_secret": "newS3cr3t...64hexchars...",
  "message": "Client secret rotated successfully. Store the new secret securely — it will not be shown again."
}
```

## Database

The service uses SQLite with a local file `./oauth_service.db`. The schema includes:

- `users` table with id, name, email, password (hashed), timestamps
- `oauth_clients` table with client credentials, redirect URIs, grant types, scopes, etc.
- Indexes on email, client_id, owner_id for performance

## Session & Token Storage

All session and token data is stored in Redis:

| Key Pattern              | TTL     | Description                       |
|--------------------------|---------|-----------------------------------|
| `session:<token>`        | 24h     | User login sessions               |
| `authcode:<code>`        | 10min   | OAuth authorization codes         |
| `access_token:<token>`   | 1h      | OAuth access tokens               |
| `refresh_token:<token>`  | 30 days | OAuth refresh tokens              |

The session cookie (`session_token`) is `HttpOnly` and `SameSite=Lax`.

## Caching

- User list cached for 5 minutes
- Individual users cached for 10 minutes
- OAuth client list cached for 5 minutes
- Individual OAuth clients cached for 10 minutes
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
main.go              - Service entry point
server/              - Server setup and route registration
handlers/
  handlers.go        - User CRUD handlers
  oauth_client.go    - OAuth client registration handlers (bearer-token)
  oauth_flow.go      - OAuth authorization code flow handlers
  auth.go            - Signup, Login, Me, Logout handlers
models/
  user.go            - User model and request types
  oauth_client.go    - OAuth client model and request types
database/
  initialize.go      - Database connection and migration
  migrations/        - SQL migration files
cache/
  initialize.go      - Redis cache initialization
static/
  index.html         - Login/Signup/Dashboard/OAuth Consent UI
```