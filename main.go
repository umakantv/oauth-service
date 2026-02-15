package main

import (
	"flag"
	"fmt"
	"oauth-service/server"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/umakantv/go-utils/db/migrations"
)

func main() {
	commandFlag := flag.String("command", "start", "Command to run modules")
	nameFlag := flag.String("name", "", "Migration name (alphanum+underscore only)")
	dirFlag := flag.String("dir", ".", "Target directory for the new .sql file (e.g. ./migrations)")
	flag.Parse()

	if *commandFlag == "" {
		fmt.Println("Usage: go run main.go --command <command-name> [... other options]")
		os.Exit(1)
	}

	switch *commandFlag {
	case "start":
		server.StartServer()
	case "create-migration":
		migrations.CreateMigration(nameFlag, dirFlag)
	}
}
