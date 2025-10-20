package middleware

import (
	"net/http"
	"strings"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware supports both user JWTs and bot internal key.
func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing Authorization header",
			})
			return
		}

		// --- BOT AUTH ---
		if strings.HasPrefix(authHeader, "Bot ") {
			token := strings.TrimPrefix(authHeader, "Bot ")
			if token == cfg.InternalAPIKey {
				c.Set("authType", "bot")
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid bot API key",
			})
			return
		}

		// --- USER AUTH ---
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := utils.ValidateJWT(token, cfg.JWTSecret)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid or expired JWT",
				})
				return
			}

			c.Set("authType", "user")
			c.Set("claims", claims)
			c.Next()
			return
		}

		// --- UNSUPPORTED AUTH METHOD ---
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "unsupported authentication type",
		})
	}
}
