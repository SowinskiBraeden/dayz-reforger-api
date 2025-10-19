package middleware

import (
	"net/http"

	"github.com/SowinskiBraeden/dayz-reforger-api/utils"

	"github.com/gin-gonic/gin"
)

func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing claims"})
			return
		}

		user := claims.(*utils.JWTClaims)
		if user.Role != role && user.Role != "admin" { // admins bypass lower roles
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}

		c.Next()
	}
}

func RequireGuildAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		guildID := c.Param("id")

		claims, exists := c.Get("claims")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token claims"})
			return
		}

		userClaims := claims.(*utils.JWTClaims)

		hasAccess := false
		for _, g := range userClaims.Guilds {
			if g == guildID {
				hasAccess = true
				break
			}
		}

		if !hasAccess {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "You do not have permission to access this guild.",
			})
			return
		}

		c.Next()
	}
}
