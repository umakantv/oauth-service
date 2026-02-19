package cache

import (
	"os"

	"github.com/umakantv/go-utils/cache"
	"github.com/umakantv/go-utils/logger"
	"go.uber.org/zap"
)

func InitializeCache() cache.Cache {
	cache, err := cache.New(cache.Config{
		Type:          "redis",
		RedisAddr:     "localhost:6379",
		RedisPassword: "",
		RedisDB:       0,
	})
	if err != nil {
		logger.Error("Failed to initialize cache:", zap.Error(err))
		os.Exit(1)
	}
	return cache
}
