package cache

import (
	"os"

	"github.com/umakantv/go-utils/cache"
	"github.com/umakantv/go-utils/logger"
	"go.uber.org/zap"
)

func InitializeCache() cache.Cache {
	// Switched to Redis for persistent session storage (as specified)
	// Assumes local Redis running at localhost:6379 (user-managed)
	// Enables cookie sessions for /login /me etc. across restarts
	config := cache.Config{
		Type:          "redis",
		RedisAddr:     "localhost:6379",
		RedisPassword: "",
		RedisDB:       0,
	}
	cache, err := cache.New(config)
	if err != nil {
		logger.Error("Failed to initialize Redis cache:", zap.Error(err))
		os.Exit(1)
	}
	logger.Info("Redis cache initialized for persistent sessions")
	return cache
}
