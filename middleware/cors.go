package middleware

import (
	"net/http"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"

	"github.com/gin-gonic/gin"
)

func CORSMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Allow only whitelisted origins
		for _, allowed := range cfg.FrontendURL {
			if origin == allowed {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}

		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == http.MethodOptions {
			// must write headers BEFORE abort
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
