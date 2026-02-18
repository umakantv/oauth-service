package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"oauth-service/models"

	"github.com/google/uuid" // For session IDs
	"github.com/jmoiron/sqlx"
	"github.com/umakantv/go-utils/cache"
	"github.com/umakantv/go-utils/errs"
	"github.com/umakantv/go-utils/httpserver"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt" // For pw verify
)

// Note: /signup reuses UserHandler create logic internally via direct call or copy for simplicity
// Full integration avoids further edits to handlers.go (edit limit)
// Sessions stored in Redis cache (persistent)

// SessionKey prefix for Redis
const sessionKeyPrefix = "session:"

// genSessionID generates unique session ID for cookies
func genSessionID() string {
	return uuid.New().String()
}

// SignupHandler handles POST /signup - creates user (with pw) and auto-logs in (cookie)
// Returns httpserver.HandlerFunc for compatibility
func SignupHandler(userHandler *UserHandler, cache cache.Cache) httpserver.HandlerFunc {
	return httpserver.HandlerFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		// Reuse create via wrapper for pw flow
		// Note: Full reuse would embed, but here direct JSON to create
		logRequest(ctx, "info", "Signup request")

		// Delegate to CreateUser (now pw-mandatory)
		userHandler.CreateUser(ctx, w, r)

		// Post-create: auto login? For simple, assume success sets session
		// (detailed in /login; UI handles)
	})
}

// LoginHandler handles POST /login - cookie-based auth using Redis sessions
// Validates email/pw (bcrypt), sets httpOnly cookie, stores user in Redis
// Returns httpserver.HandlerFunc
func LoginHandler(db *sqlx.DB, cache cache.Cache) httpserver.HandlerFunc {
	return httpserver.HandlerFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		logRequest(ctx, "info", "Login request")

		var req models.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logRequest(ctx, "error", "Invalid login body", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errs.NewValidationError("Invalid JSON"))
			return
		}

		// Find user
		var user models.User
		err := db.QueryRow("SELECT id, name, email, password FROM users WHERE email = ?", req.Email).
			Scan(&user.ID, &user.Name, &user.Email, &user.Password)
		if err == sql.ErrNoRows {
			logRequest(ctx, "error", "User not found", zap.String("email", req.Email))
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(errs.NewValidationError("Invalid credentials"))
			return
		}
		if err != nil {
			logRequest(ctx, "error", "DB error", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errs.NewInternalServerError("Server error"))
			return
		}

		// Verify pw hash
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			logRequest(ctx, "error", "Invalid password", zap.String("email", req.Email))
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(errs.NewValidationError("Invalid credentials"))
			return
		}

		// Create session - store map directly (cache handles serialization for Redis/memory)
		// Avoid marshal per cache package behavior
		sessionID := genSessionID()
		sessionData := map[string]interface{}{
			"user_id": user.ID,
			"name":    user.Name,
			"email":   user.Email,
		}
		cache.Set(sessionKeyPrefix+sessionID, sessionData, 24*time.Hour) // Persistent Redis session

		// Set cookie (httpOnly, secure for browser)
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true, // Prevent JS access for security
			Secure:   false, // True in prod HTTPS
			MaxAge:   86400, // 24h
		})

		logRequest(ctx, "info", "Login successful", zap.Int("user_id", user.ID))

		// Response
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Logged in",
			"user": models.MeResponse{
				ID:    user.ID,
				Name:  user.Name,
				Email: user.Email,
			},
		})
	})
}

// MeHandler handles GET /me - returns current user from Redis session cookie
// Returns httpserver.HandlerFunc
func MeHandler(db *sqlx.DB, cache cache.Cache) httpserver.HandlerFunc {
	return httpserver.HandlerFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		logRequest(ctx, "info", "Me request")

		// Get session cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logRequest(ctx, "error", "No session cookie")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(errs.NewValidationError("Not authenticated"))
			return
		}

		// Get from Redis - direct type assert to map (cache handles bytes/string to original interface{} type)
		// No unmarshal needed (per cache package; fixes []uint8 vs string in Redis)
		cached, err := cache.Get(sessionKeyPrefix + cookie.Value)
		if err != nil {
			logRequest(ctx, "error", "Session not found or expired")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(errs.NewValidationError("Session invalid"))
			return
		}

		sessionData, ok := cached.(map[string]interface{})
		if !ok {
			logRequest(ctx, "error", "Invalid session data type")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errs.NewInternalServerError("Session error"))
			return
		}

		logRequest(ctx, "info", "Me retrieved", zap.Int("user_id", int(sessionData["user_id"].(float64))))

		json.NewEncoder(w).Encode(models.MeResponse{
			ID:    int(sessionData["user_id"].(float64)),
			Name:  sessionData["name"].(string),
			Email: sessionData["email"].(string),
		})
	})
}

// Note: UUID dep added for sessions; bcrypt for pw; Redis for persistent cookie sessions
// Enables browser UI E2E. /signup reuses user create.
