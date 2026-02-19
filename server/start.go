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
func checkAuth(r *http.Request) (bool, httpserver.RequestAuth) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false, httpserver.RequestAuth{}
	}

	// Simple Bearer token check (in production, validate JWT)
	if len(auth) > 7 && auth[:7] == "Bearer " {
		token := auth[7:]
		if token == "secret-token" { // Simple check for demo
			return true, httpserver.RequestAuth{
				Type:   "bearer",
				Client: "user-service-client",
				Claims: map[string]interface{}{"service": "user-service"},
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

	logger.Info("Starting User Service...")

	// Initialize database
	dbConn := database.InitializeDatabase()
	defer dbConn.Close()

	// Initialize cache
	cache := cachepackage.InitializeCache()
	defer cache.Close()

	// Initialize handlers
	userHandler := handlers.NewUserHandler(dbConn, cache)
	oauthClientHandler := handlers.NewOAuthClientHandler(dbConn, cache)
	authHandler := handlers.NewAuthHandler(dbConn, cache)
	oauthFlowHandler := handlers.NewOAuthFlowHandler(dbConn, cache)

	// Create HTTP server with authentication
	server := httpserver.New("8080", checkAuth)

	// Register routes
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

	// --- Static UI route ---
	server.Register(httpserver.Route{
		Name:     "StaticUI",
		Method:   "GET",
		Path:     "/",
		AuthType: "none",
	}, httpserver.HandlerFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/index.html")
	}))

	// --- Auth routes (no bearer auth — cookie-based) ---
	server.Register(httpserver.Route{
		Name:     "Signup",
		Method:   "POST",
		Path:     "/signup",
		AuthType: "none",
	}, httpserver.HandlerFunc(authHandler.Signup))

	server.Register(httpserver.Route{
		Name:     "Login",
		Method:   "POST",
		Path:     "/login",
		AuthType: "none",
	}, httpserver.HandlerFunc(authHandler.Login))

	server.Register(httpserver.Route{
		Name:     "Me",
		Method:   "GET",
		Path:     "/me",
		AuthType: "none",
	}, httpserver.HandlerFunc(authHandler.Me))

	server.Register(httpserver.Route{
		Name:     "Logout",
		Method:   "POST",
		Path:     "/logout",
		AuthType: "none",
	}, httpserver.HandlerFunc(authHandler.Logout))

	// --- User routes ---
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

	// --- OAuth Client routes ---
	server.Register(httpserver.Route{
		Name:     "RegisterOAuthClient",
		Method:   "POST",
		Path:     "/oauth/clients",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(oauthClientHandler.RegisterClient))

	server.Register(httpserver.Route{
		Name:     "ListOAuthClients",
		Method:   "GET",
		Path:     "/oauth/clients",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(oauthClientHandler.GetClients))

	server.Register(httpserver.Route{
		Name:     "GetOAuthClient",
		Method:   "GET",
		Path:     "/oauth/clients/{id}",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(oauthClientHandler.GetClient))

	server.Register(httpserver.Route{
		Name:     "UpdateOAuthClient",
		Method:   "PUT",
		Path:     "/oauth/clients/{id}",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(oauthClientHandler.UpdateClient))

	server.Register(httpserver.Route{
		Name:     "DeleteOAuthClient",
		Method:   "DELETE",
		Path:     "/oauth/clients/{id}",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(oauthClientHandler.DeleteClient))

	server.Register(httpserver.Route{
		Name:     "RotateOAuthClientSecret",
		Method:   "POST",
		Path:     "/oauth/clients/{id}/rotate-secret",
		AuthType: "bearer",
	}, httpserver.HandlerFunc(oauthClientHandler.RotateClientSecret))

	// --- OAuth Flow routes (cookie-based / public) ---
	server.Register(httpserver.Route{
		Name:     "RegisterClientFromUI",
		Method:   "POST",
		Path:     "/oauth/register-client",
		AuthType: "none",
	}, httpserver.HandlerFunc(oauthFlowHandler.RegisterClientFromUI))

	server.Register(httpserver.Route{
		Name:     "OAuthInitialize",
		Method:   "GET",
		Path:     "/oauth/initialize",
		AuthType: "none",
	}, httpserver.HandlerFunc(oauthFlowHandler.Initialize))

	server.Register(httpserver.Route{
		Name:     "OAuthValidateInit",
		Method:   "GET",
		Path:     "/oauth/validate-init",
		AuthType: "none",
	}, httpserver.HandlerFunc(oauthFlowHandler.ValidateInitialize))

	server.Register(httpserver.Route{
		Name:     "OAuthApprove",
		Method:   "POST",
		Path:     "/oauth/approve",
		AuthType: "none",
	}, httpserver.HandlerFunc(oauthFlowHandler.Approve))

	server.Register(httpserver.Route{
		Name:     "OAuthAuthorize",
		Method:   "POST",
		Path:     "/oauth/authorize",
		AuthType: "none",
	}, httpserver.HandlerFunc(oauthFlowHandler.Authorize))

	server.Register(httpserver.Route{
		Name:     "DemoCallback",
		Method:   "GET",
		Path:     "/callback",
		AuthType: "none",
	}, httpserver.HandlerFunc(oauthFlowHandler.DemoCallback))

	logger.Info("OAuth Service started on port 8080")
	logger.Info("UI: http://localhost:8080/")
	logger.Info("Health check: GET /health")
	logger.Info("Auth endpoints: POST /signup, POST /login, GET /me, POST /logout")
	logger.Info("API endpoints: GET/POST/PUT/DELETE /users")
	logger.Info("API endpoints: GET/POST/PUT/DELETE /oauth/clients, POST /oauth/clients/{id}/rotate-secret")
	logger.Info("OAuth flow: POST /oauth/register-client, GET /oauth/initialize, POST /oauth/approve, POST /oauth/authorize")
	logger.Info("Demo callback: GET /callback")

	// Start server
	if err := server.Start(); err != nil {
		logger.Error("Server failed to start", zap.Error(err))
		os.Exit(1)
	}
}
