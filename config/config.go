package config

import (
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	MongoURI       string
	DatabaseName   string
	JWTSecret      string
	ClientID       string
	ClientSecret   string
	RedirectURI    string
	ListenAddr     string
	FrontendURL    []string
	InternalAPIKey string
}

// Load loads environment variables into the Config struct.
func Load() *Config {
	// Load .env file only in development
	_ = godotenv.Load()

	frontendEnv := getEnv("FRONTEND_URL", "http://localhost:5173")

	// Split comma-separated URLs into slice
	var frontendURLs []string
	for _, url := range strings.Split(frontendEnv, ",") {
		url = strings.TrimSpace(url)
		if url != "" {
			frontendURLs = append(frontendURLs, url)
		}
	}

	if len(frontendURLs) == 0 {
		frontendURLs = []string{"http://localhost:5173"}
	}

	cfg := &Config{
		MongoURI:       mustGetEnv("MONGO_URI"),
		DatabaseName:   getEnv("MONGO_DB", "dayzReforger"),
		JWTSecret:      mustGetEnv("JWT_SECRET"),
		ClientID:       mustGetEnv("DISCORD_CLIENT_ID"),
		ClientSecret:   mustGetEnv("DISCORD_CLIENT_SECRET"),
		RedirectURI:    mustGetEnv("DISCORD_REDIRECT_URI"),
		ListenAddr:     getEnv("LISTEN_ADDR", ":8080"),
		FrontendURL:    frontendURLs,
		InternalAPIKey: mustGetEnv("INTERNAL_API_KEY"), // 👈 new env var
	}

	log.Printf("Loaded configuration for MongoDB: %s", cfg.DatabaseName)
	return cfg
}

func mustGetEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("Missing required environment variable: %s", key)
	}
	return val
}

func getEnv(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}
