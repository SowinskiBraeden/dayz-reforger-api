package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/SowinskiBraeden/dayz-reforger-api/utils"
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

// globalLimiter: 20 requests/sec with burst of 50
var globalLimiter = newRateLimiter(20, 50)

func newRateLimiter(r rate.Limit, b int) *rateLimiter {
	utils.LogInfo("[RateLimiter] Initializing global rate limiter: %.2f req/sec, burst=%d", r, b)
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
		utils.LogInfo("[RateLimiter] Creating new limiter for key=%s", key)
		cl = &clientLimiter{
			limiter:  rate.NewLimiter(rl.r, rl.b),
			lastSeen: time.Now(),
		}
		rl.limiters[key] = cl
	} else {
		cl.lastSeen = time.Now()
	}

	return cl.limiter
}

// cleanupLoop removes old limiters that haven’t been used recently
func (rl *rateLimiter) cleanupLoop(interval time.Duration) {
	for {
		time.Sleep(interval)
		rl.mu.Lock()
		cleaned := 0
		for key, cl := range rl.limiters {
			if time.Since(cl.lastSeen) > 30*time.Minute {
				delete(rl.limiters, key)
				cleaned++
			}
		}
		rl.mu.Unlock()

		if cleaned > 0 {
			utils.LogInfo("[RateLimiter] Cleaned up %d stale limiter(s)", cleaned)
		}
	}
}

// RateLimitMiddleware applies rate limiting for user requests
func RateLimitMiddleware() gin.HandlerFunc {
	utils.LogInfo("[RateLimiter] Rate limiting middleware initialized")

	return func(c *gin.Context) {
		authType, _ := c.Get("authType")
		if authType == "bot" {
			// Skip limiting for internal bot requests
			c.Next()
			return
		}

		// Default key: client IP
		key := c.ClientIP()

		// If user is authenticated, combine userID + IP
		if claims, exists := c.Get("claims"); exists {
			if jwtClaims, ok := claims.(*utils.JWTClaims); ok && jwtClaims.UserID != "" {
				key = jwtClaims.UserID + ":" + c.ClientIP()
			}
		}

		limiter := globalLimiter.getLimiter(key)

		if !limiter.Allow() {
			utils.LogWarn("[RateLimiter] Rate limit exceeded for key=%s (IP=%s)", key, c.ClientIP())
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "too many requests, please slow down",
			})
			return
		}

		// Only log occasionally to avoid noise
		utils.LogInfo("[RateLimiter] Request allowed for key=%s", key)
		c.Next()
	}
}
