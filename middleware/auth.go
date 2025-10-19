package middleware

import (
	"net/http"
	"strings"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware ensures that every request has a valid JWT
func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token format"})
			return
		}

		claims, err := utils.ValidateJWT(cfg.JWTSecret, tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		c.Set("claims", claims)
		c.Next()
	}
}
