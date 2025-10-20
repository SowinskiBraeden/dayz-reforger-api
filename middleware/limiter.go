package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type rateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.Mutex
	r        rate.Limit
	b        int
}

var globalLimiter = newRateLimiter(2, 5) // 2 req/sec, burst of 5

func newRateLimiter(r rate.Limit, b int) *rateLimiter {
	return &rateLimiter{
		limiters: make(map[string]*rate.Limiter),
		r:        r,
		b:        b,
	}
}

func (rl *rateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(rl.r, rl.b)
		rl.limiters[key] = limiter
	}
	return limiter
}

// RateLimitMiddleware applies a per-user (or per-IP) limit.
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authType, _ := c.Get("authType")
		if authType == "bot" {
			c.Next() // skip for bot
			return
		}

		key := c.ClientIP() // fallback key
		if claims, exists := c.Get("claims"); exists {
			if jwtClaims, ok := claims.(*utils.JWTClaims); ok {
				key = jwtClaims.UserID // per-user rate limiting if logged in
			}
		}

		limiter := globalLimiter.getLimiter(key)
		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "too many requests, slow down",
			})
			return
		}

		c.Next()
	}
}
