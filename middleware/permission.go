package middleware

import (
	"net/http"

	"github.com/SowinskiBraeden/dayz-reforger-api/utils"
	"github.com/gin-gonic/gin"
)

// RequireRole ensures that the user has a required role (or admin override).
func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if !exists {
			utils.LogWarn("[RequireRole] Missing claims in request from %s", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing claims"})
			return
		}

		user := claims.(*utils.JWTClaims)
		if user.Role != role && user.Role != "admin" {
			utils.LogWarn("[RequireRole] Insufficient permissions: userID=%s role=%s required=%s", user.UserID, user.Role, role)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}

		utils.LogInfo("[RequireRole] Access granted: userID=%s role=%s (required=%s)", user.UserID, user.Role, role)
		c.Next()
	}
}

// RequireGuildAccess checks if a user (or bot) has permission to access a guild.
func RequireGuildAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		authType := c.GetString("authType")
		guildID := c.Param("id")

		// Internal bot always allowed
		if authType == "bot" {
			utils.LogInfo("[RequireGuildAccess] Internal bot access granted for guildID=%s", guildID)
			c.Next()
			return
		}

		// User auth required
		claims, ok := c.Get("claims")
		if !ok {
			utils.LogWarn("[RequireGuildAccess] Missing claims for guildID=%s from %s", guildID, c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing claims"})
			return
		}

		userClaims := claims.(*utils.JWTClaims)

		// Check guild access
		hasAccess := false
		for _, g := range userClaims.Guilds {
			if g == guildID {
				hasAccess = true
				break
			}
		}

		if !hasAccess {
			utils.LogWarn("[RequireGuildAccess] Access denied for userID=%s guildID=%s", userClaims.UserID, guildID)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "You do not have permission to access this guild.",
			})
			return
		}

		utils.LogSuccess("[RequireGuildAccess] Access granted for userID=%s guildID=%s", userClaims.UserID, guildID)
		c.Next()
	}
}
