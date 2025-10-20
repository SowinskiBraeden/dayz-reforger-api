package routes

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/db"
	"github.com/SowinskiBraeden/dayz-reforger-api/middleware"
	"github.com/SowinskiBraeden/dayz-reforger-api/models"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Cache and lock setup
var (
	guildCacheMu   sync.RWMutex
	guildCache     = make(map[string]cachedGuilds)
	guildFetchLock sync.Map
)

type cachedGuilds struct {
	guilds []models.DiscordGuild
	expiry time.Time
}

// Register guild routes under /api/guilds
func registerGuildRoutes(api *gin.RouterGroup, cfg *config.Config) {
	utils.LogInfo("Registering guild routes")

	api.GET("/guilds", GetUserGuilds)
	guilds := api.Group("/guilds")
	guilds.Use(middleware.RequireGuildAccess())

	guilds.GET("/:id/config", GetGuildConfig)
	guilds.PUT("/:id/config", UpdateGuildConfig)
}

func GetGuildConfig(c *gin.Context) {
	guildID := c.Param("id")
	utils.LogInfo("Fetching guild configuration for guildID=%s", guildID)

	var config models.GuildConfig
	collection := db.GetCollection("guilds")

	err := collection.FindOne(context.TODO(), bson.M{"server.serverID": guildID}).Decode(&config)
	if err == mongo.ErrNoDocuments {
		utils.LogWarn("Guild not found in database: %s", guildID)
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Guild not found"})
		return
	} else if err != nil {
		utils.LogError("Database error while fetching guild %s: %v", guildID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Internal database error"})
		return
	}

	utils.LogSuccess("Successfully fetched guild configuration for guildID=%s", guildID)
	c.JSON(http.StatusOK, config)
}

func GetUserGuilds(c *gin.Context) {
	claims := c.MustGet("claims").(*utils.JWTClaims)
	userID := claims.UserID
	utils.LogInfo("Fetching user guilds for userID=%s", userID)

	// Check cache
	if cached, ok := guildCache[userID]; ok && time.Now().Before(cached.expiry) {
		utils.LogInfo("Cache hit for userID=%s", userID)
		c.JSON(http.StatusOK, gin.H{"guilds": cached.guilds})
		return
	}

	// Lock per-user to prevent multiple concurrent Discord requests
	lockIface, _ := guildFetchLock.LoadOrStore(userID, &sync.Mutex{})
	lock := lockIface.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	// Double-check cache after acquiring lock
	if cached, ok := guildCache[userID]; ok && time.Now().Before(cached.expiry) {
		utils.LogInfo("Cache re-check hit for userID=%s", userID)
		c.JSON(http.StatusOK, gin.H{"guilds": cached.guilds})
		return
	}

	// Anti-burst cooldown: if last fetch was very recent
	if cached, ok := guildCache[userID]; ok && time.Since(cached.expiry.Add(-5*time.Minute)) < 5*time.Second {
		utils.LogWarn("Skipping Discord call due to cooldown for userID=%s", userID)
		c.JSON(http.StatusOK, gin.H{"guilds": cached.guilds})
		return
	}

	utils.LogInfo("Fetching guilds from Discord API for userID=%s", userID)

	// Fetch from Discord API
	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
	req.Header.Set("Authorization", "Bearer "+claims.AccessToken)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		utils.LogError("Failed to reach Discord API for userID=%s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch guilds"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		utils.LogWarn("Rate limited by Discord for userID=%s", userID)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limited by Discord"})
		return
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		utils.LogError("Discord API returned %d for userID=%s: %s", resp.StatusCode, userID, string(body))
		c.JSON(resp.StatusCode, gin.H{"error": string(body)})
		return
	}

	var guilds []models.DiscordGuild
	if err := json.NewDecoder(resp.Body).Decode(&guilds); err != nil {
		utils.LogError("Failed to decode Discord guild list for userID=%s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode guild list"})
		return
	}

	filtered := filterOwnedGuilds(guilds)
	utils.LogInfo("Fetched %d guilds (filtered to %d) for userID=%s", len(guilds), len(filtered), userID)

	// Cache for 5 minutes
	guildCache[userID] = cachedGuilds{
		guilds: filtered,
		expiry: time.Now().Add(5 * time.Minute),
	}

	utils.LogSuccess("Guilds successfully cached for userID=%s", userID)
	c.JSON(http.StatusOK, gin.H{"guilds": filtered})
}

func UpdateGuildConfig(c *gin.Context) {
	guildID := c.Param("id")
	utils.LogInfo("Updating guild configuration for guildID=%s", guildID)

	var payload models.GuildConfig
	if err := c.BindJSON(&payload); err != nil {
		utils.LogError("Invalid JSON in UpdateGuildConfig for guildID=%s: %v", guildID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"server.serverID": guildID}
	update := bson.M{"$set": bson.M{"server": payload.Server}}

	collection := db.GetCollection("guilds")
	res, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		utils.LogError("Database error updating guildID=%s: %v", guildID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to update configuration",
		})
		return
	}

	if res.MatchedCount == 0 {
		utils.LogWarn("Attempted to update non-existent guildID=%s", guildID)
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Guild not found",
		})
		return
	}

	utils.LogSuccess("Successfully updated guild configuration for guildID=%s", guildID)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Guild configuration updated successfully",
	})
}

func filterOwnedGuilds(guilds []models.DiscordGuild) []models.DiscordGuild {
	var filtered []models.DiscordGuild
	for _, g := range guilds {
		if g.Owner {
			filtered = append(filtered, g)
		}
		// In future: add permission bit checks
	}
	return filtered
}
