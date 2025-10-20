package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"yourapp/utils" // adjust import path for JWTClaims
)

// rateLimiter tracks limiters per key (user/IP) and cleans them up
type rateLimiter struct {
	limiters map[string]*clientLimiter
	mu       sync.Mutex
	r        rate.Limit
	b        int
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var globalLimiter = newRateLimiter(3, 8) // 3 req/sec, burst 8

func newRateLimiter(r rate.Limit, b int) *rateLimiter {
	rl := &rateLimiter{
		limiters: make(map[string]*clientLimiter),
		r:        r,
		b:        b,
	}

	// Periodically clean up stale entries
	go rl.cleanupLoop(10 * time.Minute)
	return rl
}

func (rl *rateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cl, exists := rl.limiters[key]
	if !exists {
		cl = &clientLimiter{
			limiter:  rate.NewLimiter(rl.r, rl.b),
			lastSeen: time.Now(),
		}
		rl.limiters[key] = cl
	}

	cl.lastSeen = time.Now()
	return cl.limiter
}

// cleanupLoop removes old limiters that haven’t been used recently
func (rl *rateLimiter) cleanupLoop(interval time.Duration) {
	for {
		time.Sleep(interval)
		rl.mu.Lock()
		for key, cl := range rl.limiters {
			if time.Since(cl.lastSeen) > 30*time.Minute {
				delete(rl.limiters, key)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware applies rate limiting for user requests
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authType, _ := c.Get("authType")
		if authType == "bot" {
			c.Next()
			return
		}

		// Default key is the client IP
		key := c.ClientIP()

		// If user authenticated, use hybrid key: userID:IP
		if claims, exists := c.Get("claims"); exists {
			if jwtClaims, ok := claims.(*utils.JWTClaims); ok && jwtClaims.UserID != "" {
				key = jwtClaims.UserID + ":" + c.ClientIP()
			}
		}

		// Get limiter for this key
		limiter := globalLimiter.getLimiter(key)

		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "too many requests, please slow down",
			})
			return
		}

		c.Next()
	}
}
