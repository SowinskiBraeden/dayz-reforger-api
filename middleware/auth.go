package middleware

import (
	"net/http"
	"strings"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware validates both user JWTs and bot internal API keys.
func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			utils.LogWarn("[AuthMiddleware] Missing Authorization header from %s", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing Authorization header",
			})
			return
		}

		if strings.HasPrefix(authHeader, "Bot ") {
			token := strings.TrimPrefix(authHeader, "Bot ")
			if token == cfg.InternalAPIKey {
				utils.LogSuccess("[AuthMiddleware] Authorized internal bot request from %s", c.ClientIP())
				c.Set("authType", "bot")
				c.Next()
				return
			}

			utils.LogError("[AuthMiddleware] Invalid bot API key from %s", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid bot API key",
			})
			return
		}

		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")

			claims, err := utils.ValidateJWT(cfg.JWTSecret, token)
			if err != nil {
				utils.LogError("[AuthMiddleware] Invalid or expired JWT from %s: %v", c.ClientIP(), err)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid or expired JWT",
				})
				return
			}

			utils.LogInfo("[AuthMiddleware] Authorized user JWT for userID=%s from %s", claims.UserID, c.ClientIP())
			c.Set("authType", "user")
			c.Set("claims", claims)
			c.Next()
			return
		}

		utils.LogWarn("[AuthMiddleware] Unsupported Authorization type from %s: %s", c.ClientIP(), authHeader)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "unsupported authentication type",
		})
	}
}
