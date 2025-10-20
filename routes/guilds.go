package routes

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/db"
	"github.com/SowinskiBraeden/dayz-reforger-api/middleware"
	"github.com/SowinskiBraeden/dayz-reforger-api/models"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"

	"context"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Cache and lock setup
var (
	guildCacheMu sync.RWMutex
	guildCache   = make(map[string]cachedGuilds)

	guildFetchLock sync.Map
)

type cachedGuilds struct {
	guilds []models.DiscordGuild
	expiry time.Time
}

// Register guild routes under /api/guilds
func registerGuildRoutes(api *gin.RouterGroup, cfg *config.Config) {
	api.GET("/guilds", GetUserGuilds)

	guilds := api.Group("/guilds")
	guilds.Use(middleware.RequireGuildAccess())

	guilds.GET("/:id/config", GetGuildConfig)
	guilds.PUT("/:id/config", UpdateGuildConfig)
}

func GetGuildConfig(c *gin.Context) {
	guildID := c.Param("id")

	var config models.GuildConfig
	collection := db.GetCollection("guilds")

	err := collection.FindOne(context.TODO(), bson.M{"server.serverID": guildID}).Decode(&config)
	if err == mongo.ErrNoDocuments {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Guild not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Internal database error"})
		return
	}

	// Identify request type
	authType, _ := c.Get("authType") // set by middleware
	isInternal := authType == "bot" || c.GetHeader("X-Internal-Key") == os.Getenv("INTERNAL_API_KEY")

	// Sanitize for user-facing requests
	if !isInternal {
		config.Nitrado.Auth = "" // never expose raw creds
	}

	c.JSON(http.StatusOK, config)
}

// filterOwnedGuilds filters the guild list to include only those the user owns
// or has MANAGE_GUILD or ADMINISTRATOR permissions on.
func filterOwnedGuilds(guilds []models.DiscordGuild) []models.DiscordGuild {
	var filtered []models.DiscordGuild

	for _, g := range guilds {
		// Discord permission flags:
		// ADMINISTRATOR (0x8) or MANAGE_GUILD (0x20)
		// const (
		// 	PermissionAdministrator = 0x8
		// 	PermissionManageGuild   = 0x20
		// )

		// owner always allowed
		if g.Owner {
			filtered = append(filtered, g)
			continue
		}

		// check if they have required permissions
		// if (g.Permissions & (PermissionAdministrator | PermissionManageGuild)) != 0 {
		// 	filtered = append(filtered, g)
		// }
	}

	return filtered
}

func GetUserGuilds(c *gin.Context) {
	claims := c.MustGet("claims").(*utils.JWTClaims)
	userID := claims.UserID

	// Check cache
	if cached, ok := guildCache[userID]; ok && time.Now().Before(cached.expiry) {
		c.JSON(http.StatusOK, gin.H{"guilds": cached.guilds})
		return
	}

	// Create or get lock for this user
	lockIface, _ := guildFetchLock.LoadOrStore(userID, &sync.Mutex{})
	lock := lockIface.(*sync.Mutex)

	// Prevent multiple Discord calls for same user
	lock.Lock()
	defer lock.Unlock()

	// Check again after waiting for lock (another goroutine may have fetched)
	if cached, ok := guildCache[userID]; ok && time.Now().Before(cached.expiry) {
		c.JSON(http.StatusOK, gin.H{"guilds": cached.guilds})
		return
	}

	// simple anti-burst cooldown
	if cached, ok := guildCache[userID]; ok && time.Since(cached.expiry.Add(-5*time.Minute)) < 5*time.Second {
		// another fetch within 5s of last success -> skip Discord call
		c.JSON(http.StatusOK, gin.H{"guilds": cached.guilds})
		return
	}

	// Fetch from Discord once
	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
	req.Header.Set("Authorization", "Bearer "+claims.AccessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch guilds"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limited by Discord"})
		return
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.JSON(resp.StatusCode, gin.H{"error": string(body)})
		return
	}

	var guilds []models.DiscordGuild
	if err := json.NewDecoder(resp.Body).Decode(&guilds); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode guild list"})
		return
	}

	filtered := filterOwnedGuilds(guilds)

	// Save to cache (5 min)
	guildCache[userID] = cachedGuilds{
		guilds: filtered,
		expiry: time.Now().Add(5 * time.Minute),
	}

	c.JSON(http.StatusOK, gin.H{"guilds": filtered})
}

func UpdateGuildConfig(c *gin.Context) {
	guildID := c.Param("id")

	// Parse JSON body
	var payload models.GuildConfig
	if err := c.BindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	// Update in Mongo
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"server.serverID": guildID}
	update := bson.M{"$set": bson.M{
		"server": payload.Server,
	}}

	collection := db.GetCollection("guilds")
	res, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to update configuration",
		})
		return
	}

	if res.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Guild not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Guild configuration updated successfully",
	})
}
