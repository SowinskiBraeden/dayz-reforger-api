package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/db"
	"github.com/SowinskiBraeden/dayz-reforger-api/routes"

	"github.com/SowinskiBraeden/dayz-reforger-api/middleware"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"
	"github.com/gin-gonic/gin"
)

func main() {
	utils.InitSessionLogger()

	cfg := config.Load()
	db.Connect(cfg.MongoURI, cfg.DatabaseName)
	defer db.Disconnect()

	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(
		middleware.LoggingMiddleware(),
		middleware.CORSMiddleware(cfg),
		gin.Recovery(),
	)

	router.SetTrustedProxies([]string{"127.0.0.1", "::1"})

	// Register all routes (auth, guilds, etc.)
	routes.RegisterRoutes(router, cfg)

	// Start the server
	go func() {
		log.Printf("Server running on %s", cfg.ListenAddr)
		if err := router.Run(cfg.ListenAddr); err != nil {
			log.Fatalf("Failed to start: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")
}
