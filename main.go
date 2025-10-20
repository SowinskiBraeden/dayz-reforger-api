package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/db"
	"github.com/SowinskiBraeden/dayz-reforger-api/middleware"
	"github.com/SowinskiBraeden/dayz-reforger-api/routes"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"

	"github.com/gin-gonic/gin"
)

func main() {
	utils.InitSessionLogger()
	utils.LogInfo("[Main] Starting DayZ Reforger API Service")

	cfg := config.Load()
	db.Connect(cfg.MongoURI, cfg.DatabaseName)
	defer db.Disconnect()

	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
		utils.LogInfo("[Main] Gin set to Release mode (default)")
	} else {
		utils.LogInfo("[Main] Gin mode: %s", os.Getenv("GIN_MODE"))
	}

	router := gin.New()
	router.Use(
		middleware.LoggingMiddleware(),
		middleware.CORSMiddleware(cfg),
		middleware.RateLimitMiddleware(),
		gin.Recovery(),
	)
	router.SetTrustedProxies([]string{"127.0.0.1", "::1"})

	utils.LogInfo("[Main] Registering routes...")
	routes.RegisterRoutes(router, cfg)

	for _, r := range router.Routes() {
		utils.LogInfo("[Router] %-6s %s", r.Method, r.Path)
	}
	utils.LogSuccess("[Main] All routes registered successfully")
	utils.LogSuccess("[Main] API ready on %s | DB=%s | Frontend=%s",
		cfg.ListenAddr, cfg.DatabaseName, cfg.FrontendURL[0])

	// Start API
	go func() {
		utils.LogSuccess("[Main] Server running on %s", cfg.ListenAddr)
		if err := router.Run(cfg.ListenAddr); err != nil {
			utils.LogError("[Main] Failed to start server: %v", err)
			os.Exit(1)
		}
	}()

	// Gracefull shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	utils.LogWarn("[Main] Shutdown signal received — cleaning up...")

	// Add small grace period before disconnect
	time.Sleep(1 * time.Second)
	db.Disconnect()

	utils.LogSuccess("[Main] Server shutdown completed gracefully")
}
