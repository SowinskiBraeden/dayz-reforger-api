package routes

import (
	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/middleware"

	"net/http"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes sets up all route groups
func RegisterRoutes(router *gin.Engine, cfg *config.Config) {

	// Share config across requests
	router.Use(func(c *gin.Context) {
		c.Set("config", cfg)
		c.Next()
	})

	router.GET("/api/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "online"})
	})

	// Public auth routes
	router.GET("/auth/discord/login", DiscordLogin)
	router.GET("/auth/discord/callback", DiscordCallback)
	router.GET("/auth/nitrado/login", NitradoLogin)
	router.GET("/auth/nitrado/callback", NitradoCallback)

	// Protected API group
	api := router.Group("/api")
	api.Use(middleware.AuthMiddleware())

	// Auth routes (protected)
	api.GET("/auth/me", Me)

	// Guild config routes (protected)
	registerGuildRoutes(api, cfg)
	registerNitradoRoutes(api, cfg)
}
