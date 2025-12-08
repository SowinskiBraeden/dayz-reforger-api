package middleware

import (
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		duration := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method
		path := c.Request.URL.Path
		clientIP := c.ClientIP()

		color := "\033[32m"
		if status >= 400 && status < 500 {
			color = "\033[33m"
		} else if status >= 500 {
			color = "\033[31m"
		}
		reset := "\033[0m"

		// Truncate the path to keep columns aligned
		const maxPathLen = 40
		if len(path) > maxPathLen {
			path = path[:maxPathLen-3] + "..."
		}

		// Format duration consistently (milliseconds) with fixed width
		ms := duration.Milliseconds()
		durationStr := fmt.Sprintf("%dms", ms)
		durationStr = fmt.Sprintf("%7s", durationStr) // pad to 7 chars

		// Pad client IP to keep alignment
		clientIPPad := fmt.Sprintf("%15s", clientIP)

		message := fmt.Sprintf("%s%-6s%s %-40s | %s%3d%s | %7s | %s",
			color, method, reset, path, color, status, reset, durationStr, clientIPPad,
		)

		log.Print(message)
	}
}
