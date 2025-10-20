package config

import (
	"os"
	"strings"

	"github.com/SowinskiBraeden/dayz-reforger-api/utils"
	"github.com/joho/godotenv"
)

// Config holds all environment configuration values
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

func Load() *Config {
	utils.LogInfo("[Config] Loading environment configuration")

	// Load .env file only in development
	if err := godotenv.Load(); err == nil {
		utils.LogInfo("[Config] Loaded .env file successfully")
	} else {
		utils.LogWarn("[Config] No .env file found, using system environment variables")
	}

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
		utils.LogWarn("[Config] FRONTEND_URL missing, defaulting to %s", frontendURLs[0])
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
		InternalAPIKey: mustGetEnv("INTERNAL_API_KEY"),
	}

	utils.LogSuccess("[Config] Configuration loaded successfully")
	utils.LogInfo("[Config] MongoDB: %s | Listen: %s | Frontend: %v", cfg.DatabaseName, cfg.ListenAddr, cfg.FrontendURL)

	return cfg
}

func mustGetEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		utils.LogError("[Config] Missing required environment variable: %s", key)
		panic("missing required environment variable: " + key)
	}
	return val
}

func getEnv(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		utils.LogWarn("[Config] Using default value for %s: %s", key, def)
		return def
	}
	return val
}
