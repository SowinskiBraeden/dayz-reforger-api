package routes

import (
	"log"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/middleware"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes sets up all route groups
func RegisterRoutes(router *gin.Engine, cfg *config.Config) {

	log.Println("Registering routes...")
	for _, r := range router.Routes() {
		log.Printf("%s %s", r.Method, r.Path)
	}

	// Share config across requests
	router.Use(func(c *gin.Context) {
		c.Set("config", cfg)
		c.Next()
	})

	// Public auth routes
	router.GET("/auth/discord/login", DiscordLogin)
	router.GET("/auth/discord/callback", DiscordCallback)

	// Protected API group
	api := router.Group("/api")
	api.Use(middleware.AuthMiddleware(cfg))

	// Auth routes (protected)
	api.GET("/auth/me", Me)

	// Guild config routes (protected)
	registerGuildRoutes(api, cfg)
}
