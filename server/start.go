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
		w.Write([]byte(`{"status": "healthy", "service": "user-service"}`))
	}))

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

	logger.Info("User Service started on port 8080")
	logger.Info("Health check: GET /health")
	logger.Info("API endpoints: GET/POST/PUT/DELETE /users")

	// Start server
	if err := server.Start(); err != nil {
		logger.Error("Server failed to start", zap.Error(err))
		os.Exit(1)
	}
}
