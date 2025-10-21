package config

import (
	"os"
	"strings"

	"github.com/SowinskiBraeden/dayz-reforger-api/utils"
	"github.com/joho/godotenv"
)

// Config holds all environment configuration values
type Config struct {
	MongoURI            string   `env:"MONGO_URI"`
	DatabaseName        string   `env:"MONGO_DB"`
	JWTSecret           string   `env:"JWT_SECRET"`
	DiscordClientID     string   `env:"DISCORD_CLIENT_ID"`
	DiscordClientSecret string   `env:"DISCORD_CLIENT_SECRET"`
	DiscordRedirectURI  string   `env:"DISCORD_REDIRECT_URI"`
	ListenAddr          string   `env:"LISTEN_ADDR"`
	FrontendURL         []string `env:"FRONTEND_URL"`
	InternalAPIKey      string   `env:"INTERNAL_API_KEY"`
	NitradoClientID     string   `env:"NITRADO_CLIENT_ID"`
	NitradoClientSecret string   `env:"NITRADO_CLIENT_SECRET"`
	NitradoRedirectURI  string   `env:"NITRADO_REDIRECT_URI"`
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
		MongoURI:            mustGetEnv("MONGO_URI"),
		DatabaseName:        getEnv("MONGO_DB", "dayzReforger"),
		JWTSecret:           mustGetEnv("JWT_SECRET"),
		DiscordClientID:     mustGetEnv("DISCORD_CLIENT_ID"),
		DiscordClientSecret: mustGetEnv("DISCORD_CLIENT_SECRET"),
		DiscordRedirectURI:  mustGetEnv("DISCORD_REDIRECT_URI"),
		ListenAddr:          getEnv("LISTEN_ADDR", ":8080"),
		FrontendURL:         frontendURLs,
		InternalAPIKey:      mustGetEnv("INTERNAL_API_KEY"),
		NitradoClientID:     mustGetEnv("NITRADO_CLIENT_ID"),
		NitradoClientSecret: mustGetEnv("NITRADO_CLIENT_SECRET"),
		NitradoRedirectURI:  mustGetEnv("NITRADO_REDIRECT_URI"),
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
