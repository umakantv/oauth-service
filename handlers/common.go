package handlers

import (
	"context"
	"time"

	"github.com/umakantv/go-utils/httpserver"
	logger "github.com/umakantv/go-utils/logger"
	"go.uber.org/zap"
)

// logRequest logs the request with the specified format
// This is now a shared package-level function (in handlers/common.go) to eliminate
// duplication between UserHandler and OAuthClientHandler.
// It reuses httpserver context utils for route/auth details and structured logging.
// Calls are now `logRequest(...)` instead of `h.logRequest(...)` for reusability.
// Matches sample: logger.Info("msg", fields...) ; uses zap.Error for errors etc.
// In future, could expand to a base struct/interface if more shared logic needed.
func logRequest(ctx context.Context, level string, message string, fields ...zap.Field) {
	routeName := httpserver.GetRouteName(ctx)
	method := httpserver.GetRouteMethod(ctx)
	path := httpserver.GetRoutePath(ctx)
	auth := httpserver.GetRequestAuth(ctx)

	// Build full message consistent with existing (timestamp - route - method - path - client)
	logMsg := time.Now().Format("2006-01-02 15:04:05") + " - " + routeName + " - " + method + " - " + path
	if auth != nil {
		logMsg += " - client:" + auth.Client
	}
	// Append custom message for clarity
	if message != "" {
		logMsg += " - " + message
	}

	// Add custom fields (route etc + any passed , e.g. zap.Error(err) for errors)
	allFields := append([]zap.Field{
		zap.String("route", routeName),
		zap.String("method", method),
		zap.String("path", path),
	}, fields...)

	switch level {
	case "info":
		logger.Info(logMsg, allFields...)
	case "error":
		logger.Error(logMsg, allFields...)
	case "debug":
		logger.Debug(logMsg, allFields...)
	}
}
