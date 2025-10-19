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

		message := fmt.Sprintf("%s%-6s%s %-40s | %s%-3d%s | %-10v | %s",
			color, method, reset, path, color, status, reset, duration, clientIP,
		)

		log.Print(message)
	}
}
