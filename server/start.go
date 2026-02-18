package server

import (
	"context"
	"net/http"
	cachepackage "oauth-service/cache"
	"oauth-service/database"
	"oauth-service/handlers"
	"os"

	"github.com/umakantv/go-utils/httpserver"
	"github.com/umakantv/go-utils/logger"
	"go.uber.org/zap"
)

// checkAuth implements authentication for the service
// All protected endpoints (users, oauth/clients) require this
// For the OAuth server itself, future token endpoints will use different auth logic
// based on client configs (e.g., validate client_id, redirect_uris, etc.)
func checkAuth(r *http.Request) (bool, httpserver.RequestAuth) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false, httpserver.RequestAuth{}
	}

	// Simple Bearer token check (in production, validate JWT or API key)
	if len(auth) > 7 && auth[:7] == "Bearer " {
		token := auth[7:]
		if token == "secret-token" { // Simple check for demo
			return true, httpserver.RequestAuth{
				Type: "bearer",
				// Updated for OAuth service context
				Client: "oauth-service-admin",
				Claims: map[string]interface{}{"service": "oauth-service"},
			}
		}
	}

	return false, httpserver.RequestAuth{}
}

func StartServer() {
	// Initialize logger
	logger.Init(logger.LoggerConfig{
		CallerKey:  "file",
		TimeKey:    "timestamp",
		CallerSkip: 1,
	})

	logger.Info("Starting OAuth Service...")

	// Initialize database
	// Migrations include users table and updated oauth_client table
	// with support for client configs like redirect_uris (allowed callbacks)
	dbConn := database.InitializeDatabase()
	defer dbConn.Close()

	// Initialize cache
	cache := cachepackage.InitializeCache()
	defer cache.Close()

	// Initialize handlers
	// Keep user APIs as mentioned for managing users in DB
	userHandler := handlers.NewUserHandler(dbConn, cache)
	// Add OAuth client handler for registering OAuth clients and configs
	oauthHandler := handlers.NewOAuthClientHandler(dbConn, cache)
	// Add token handler for standard OAuth /token endpoint (code -> access/refresh)
	// Uses client validation from oauth_client table
	oauthTokenHandler := handlers.NewOAuthTokenHandler(dbConn, cache)

	// Auth handlers for cookie-based flows using Redis sessions (pw from updated users)
	// /signup reuses user create, /login /me for browser UI E2E

	// OAuth authorize handler for confirmation page + code issuance
	// Validates standard params (client_id, redirect_uri, scope), user session, client config
	// Uses Redis for auth code with TTL expiry; error if no login
	// Enables full OAuth browser flow
	oauthAuthHandler := handlers.NewOAuthAuthorizeHandler(dbConn, cache)

	// Create HTTP server with authentication
	// Note: /oauth/clients* APIs are protected by bearer token (admin)
	// Future OAuth endpoints (e.g., /authorize, /token) may have different auth
	server := httpserver.New("3001", checkAuth)

	// Register routes
	// Health check (public)
	server.Register(httpserver.Route{
		Name:     "HealthCheck",
		Method:   "GET",
		Path:     "/health",
		AuthType: "none",
	}, httpserver.HandlerFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "healthy", "service": "oauth-service"}`))
	}))

	// User management routes (as per original boilerplate and for /users... APIs)
	server.Register(httpserver.Route{
		Name:     "ListUsers",
		Method:   "GET",
		Path:     "/users",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(userHandler.GetUsers))

	server.Register(httpserver.Route{
		Name:     "GetUser",
		Method:   "GET",
		Path:     "/users/{id}",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(userHandler.GetUser))

	server.Register(httpserver.Route{
		Name:     "CreateUser",
		Method:   "POST",
		Path:     "/users",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(userHandler.CreateUser))

	server.Register(httpserver.Route{
		Name:     "UpdateUser",
		Method:   "PUT",
		Path:     "/users/{id}",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(userHandler.UpdateUser))

	server.Register(httpserver.Route{
		Name:     "DeleteUser",
		Method:   "DELETE",
		Path:     "/users/{id}",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(userHandler.DeleteUser))

	// OAuth clients routes - for registering OAuth clients and their necessary configurations
	// e.g., name, redirect_uris (allowed callback URLs), scopes, etc.
	// This fulfills the request for OAuth client registration APIs
	server.Register(httpserver.Route{
		Name:     "ListOAuthClients",
		Method:   "GET",
		Path:     "/oauth/clients",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(oauthHandler.GetOAuthClients))

	server.Register(httpserver.Route{
		Name:     "GetOAuthClient",
		Method:   "GET",
		Path:     "/oauth/clients/{id}",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(oauthHandler.GetOAuthClient))

	server.Register(httpserver.Route{
		Name:     "CreateOAuthClient",
		Method:   "POST",
		Path:     "/oauth/clients",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(oauthHandler.CreateOAuthClient))

	server.Register(httpserver.Route{
		Name:     "UpdateOAuthClient",
		Method:   "PUT",
		Path:     "/oauth/clients/{id}",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(oauthHandler.UpdateOAuthClient))

	server.Register(httpserver.Route{
		Name:     "DeleteOAuthClient",
		Method:   "DELETE",
		Path:     "/oauth/clients/{id}",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(oauthHandler.DeleteOAuthClient))

	// OAuth token endpoint - standard /oauth/token for exchanging auth code -> access/refresh tokens
	// AuthType: "none" (validates client_id/secret + code/redirect_uri internally against client config)
	// Supports grant_type=authorization_code for simple OAuth server
	server.Register(httpserver.Route{
		Name:     "Token",
		Method:   "POST",
		Path:     "/oauth/token",
		AuthType: "none",
	}, httpserver.HandlerFunc(oauthTokenHandler.HandleToken))

	// Auth routes for cookie-based signup/login/me (no bearer; uses Redis sessions + pw)
	// /signup reuses UserHandler.CreateUser (now pw-mandatory)
	// Enables browser UI E2E flow
	server.Register(httpserver.Route{
		Name:     "Signup",
		Method:   "POST",
		Path:     "/signup",
		AuthType: "none",
	}, httpserver.HandlerFunc(handlers.SignupHandler(userHandler, cache)))

	server.Register(httpserver.Route{
		Name:     "Login",
		Method:   "POST",
		Path:     "/login",
		AuthType: "none",
	}, httpserver.HandlerFunc(handlers.LoginHandler(dbConn, cache)))

	server.Register(httpserver.Route{
		Name:     "Me",
		Method:   "GET",
		Path:     "/me",
		AuthType: "none",
	}, httpserver.HandlerFunc(handlers.MeHandler(dbConn, cache)))

	// OAuth authorize routes for confirmation page + code issuance
	// GET /oauth/authorize?client_id=...&redirect_uri=...&scope=... (standard params)
	// Validates user session, client config; error if no login ("User is not logged in")
	// POST /oauth/authorize/approve for code gen + Redis TTL store + callback redirect
	// Enables full browser OAuth flow
	server.Register(httpserver.Route{
		Name:     "Authorize",
		Method:   "GET",
		Path:     "/oauth/authorize",
		AuthType: "none",
	}, httpserver.HandlerFunc(oauthAuthHandler.HandleAuthorize))

	// Approve handler returns httpserver.HandlerFunc
	server.Register(httpserver.Route{
		Name:     "AuthorizeApprove",
		Method:   "POST",
		Path:     "/oauth/authorize/approve",
		AuthType: "none",
	}, oauthAuthHandler.HandleApprove())

	// Callback route for /oauth/callback?code=...&client_id=... (server-side exchange , hides secret)
	// Also handle /cb for redirect_uri landing (browser/UI)
	server.Register(httpserver.Route{
		Name:     "OAuthCallback",
		Method:   "GET",
		Path:     "/oauth/callback",
		AuthType: "none",
	}, httpserver.HandlerFunc(oauthAuthHandler.HandleCallback))

	// /cb for sample redirect (can extend static serve , but dedicated for flow)
	server.Register(httpserver.Route{
		Name:     "CallbackPage",
		Method:   "GET",
		Path:     "/cb",
		AuthType: "none",
	}, httpserver.HandlerFunc(oauthAuthHandler.HandleCallback))

	// Serve static UI at root for browser testing (forms for all flows)
	// UI at http://localhost:8080/ - handles cookies/fetch to APIs
	server.Register(httpserver.Route{
		Name:     "StaticUI",
		Method:   "GET",
		Path:     "/",
		AuthType: "none",
	}, httpserver.HandlerFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			http.ServeFile(w, r, "./static/index.html")
			return
		}
		http.NotFound(w, r)
	}))

	logger.Info("OAuth Service started on port 8080")
	logger.Info("Health check: GET /health")
	logger.Info("User management: GET/POST/PUT/DELETE /users")
	logger.Info("OAuth clients (for registration and callback configs): GET/POST/PUT/DELETE /oauth/clients")
	logger.Info("OAuth token endpoint (code exchange for access/refresh tokens): POST /oauth/token")
	logger.Info("Auth flows (cookie sessions via Redis): POST /signup, POST /login, GET /me")
	logger.Info("OAuth authorize (confirm page + code in Redis): GET/POST /oauth/authorize")
	logger.Info("Browser UI for E2E testing: GET / (static/index.html)")

	// Start server
	if err := server.Start(); err != nil {
		logger.Error("Server failed to start", zap.Error(err))
		os.Exit(1)
	}
}
