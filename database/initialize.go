package database

import (
	"os"

	"github.com/jmoiron/sqlx"
	"github.com/umakantv/go-utils/db"
	"github.com/umakantv/go-utils/db/migrations"
	"github.com/umakantv/go-utils/logger"
	"go.uber.org/zap"
)

func InitializeDatabase() *sqlx.DB {
	// Database configuration for SQLite
	config := db.DatabaseConfig{
		DRIVER: "sqlite3",
		DB:     "./oauth_service.db",
	}

	dbConn := db.GetDBConnection(config)

	err := migrations.Migrate(dbConn, "./database/migrations")
	if err != nil {
		logger.Error("Error while running migration", zap.Error(err))
		os.Exit(1)
	}

	logger.Info("Database initialized successfully")
	return dbConn
}
