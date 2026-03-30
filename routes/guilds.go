package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/db"
	"github.com/SowinskiBraeden/dayz-reforger-api/middleware"
	"github.com/SowinskiBraeden/dayz-reforger-api/models"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"
	"github.com/go-playground/validator/v10"

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
	api.GET("/guilds/linked", GetLinkedGuilds)

	guilds := api.Group("/guilds")
	guilds.Use(middleware.RequireGuildAccess())

	guilds.POST("/:id/link", LinkGuild)
	guilds.POST("/:id/unlink", UnlinkGuild)
	guilds.GET("/:id/config", GetGuildConfig)
	guilds.PUT("/:id/config", UpdateGuildConfig)
	guilds.GET("/:id/channels", GetGuildChannels)
	guilds.GET("/:id/roles", GetGuildRoles)

	guilds.GET("/:id/readiness", GetGuildReadiness)
	guilds.POST("/:id/activate", ActivateGuild)
	guilds.POST("/:id/deactivate", DeactivateGuild)
}

func GetGuildConfig(c *gin.Context) {
	guildID := c.Param("id")
	utils.LogInfo("Fetching guild configuration for guildID=%s", guildID)

	var config models.GuildConfig
	collection := db.GetCollection("guilds")

	err := collection.FindOne(context.TODO(), bson.M{"server.server_id": guildID}).Decode(&config)
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

func GetGuildChannels(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)
	guildID := c.Param("id")

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("https://discord.com/api/guilds/%s/channels", guildID),
		nil,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create discord request"})
		return
	}

	req.Header.Set("Authorization", "Bot "+cfg.DiscordBotToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch channels from discord"})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Bot is not in guild or lacks access
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		inviteURL := fmt.Sprintf(
			"https://discord.com/api/oauth2/authorize?client_id=%s&permissions=4503602311982144&scope=bot%%20applications.commands",
			cfg.DiscordClientID,
		)

		c.JSON(http.StatusOK, gin.H{
			"bot_present": false,
			"channels":    []models.DiscordChannel{},
			"invite_url":  inviteURL,
		})
		return
	}

	// Invalid bot token or Discord auth issue
	if resp.StatusCode == http.StatusUnauthorized {
		utils.LogError("[GetGuildChannels] Discord bot auth failed for guildID=%s: %s", guildID, string(body))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "discord bot authentication failed",
		})
		return
	}

	if resp.StatusCode != http.StatusOK {
		utils.LogError("[GetGuildChannels] Discord API returned %d for guildID=%s: %s", resp.StatusCode, guildID, string(body))
		c.JSON(http.StatusBadGateway, gin.H{
			"error":  "discord API error",
			"detail": string(body),
		})
		return
	}

	var channels []models.DiscordChannel
	if err := json.Unmarshal(body, &channels); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode channels"})
		return
	}

	filtered := make([]models.DiscordChannel, 0)
	for _, ch := range channels {
		// 0 = guild text, 5 = announcement/news
		if ch.Type == 0 || ch.Type == 5 {
			filtered = append(filtered, ch)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].ParentID == filtered[j].ParentID {
			return filtered[i].Position < filtered[j].Position
		}
		return filtered[i].ParentID < filtered[j].ParentID
	})

	c.JSON(http.StatusOK, gin.H{
		"bot_present": true,
		"channels":    filtered,
	})
}

func GetGuildRoles(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)
	guildID := c.Param("id")

	req, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("https://discord.com/api/guilds/%s/roles", guildID),
		nil,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create discord request",
		})
		return
	}

	req.Header.Set("Authorization", "Bot "+cfg.DiscordBotToken)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		utils.LogError("[GetGuildRoles] failed request for guildID=%s: %v", guildID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to fetch roles from discord",
		})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.LogError("[GetGuildRoles] failed reading response body for guildID=%s: %v", guildID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to read discord response",
		})
		return
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		inviteURL := fmt.Sprintf(
			"https://discord.com/api/oauth2/authorize?client_id=%s&permissions=2147560512&scope=bot%%20applications.commands",
			cfg.DiscordClientID,
		)

		c.JSON(http.StatusOK, gin.H{
			"bot_present": false,
			"roles":       []models.DiscordRole{},
			"invite_url":  inviteURL,
		})
		return
	}

	if resp.StatusCode == http.StatusUnauthorized {
		utils.LogError("[GetGuildRoles] discord bot auth failed for guildID=%s: %s", guildID, string(body))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "discord bot authentication failed",
		})
		return
	}

	if resp.StatusCode != http.StatusOK {
		utils.LogError("[GetGuildRoles] discord API returned %d for guildID=%s: %s", resp.StatusCode, guildID, string(body))
		c.JSON(http.StatusBadGateway, gin.H{
			"error":  "discord API error",
			"detail": string(body),
		})
		return
	}

	var roles []models.DiscordRole
	if err := json.Unmarshal(body, &roles); err != nil {
		utils.LogError("[GetGuildRoles] failed to decode roles for guildID=%s: %v", guildID, err)
		utils.LogError("[GetGuildRoles] raw body: %s", string(body))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to decode roles",
		})
		return
	}

	filtered := make([]models.DiscordRole, 0, len(roles))
	for _, role := range roles {
		if role.ID == guildID {
			continue
		}

		filtered = append(filtered, role)
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Position == filtered[j].Position {
			return filtered[i].Name < filtered[j].Name
		}

		return filtered[i].Position > filtered[j].Position
	})

	c.JSON(http.StatusOK, gin.H{
		"bot_present": true,
		"roles":       filtered,
	})
}

func GetUserGuilds(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)
	claims := c.MustGet("claims").(*utils.JWTClaims)
	userID := claims.UserID
	utils.LogInfo("[GetUserGuilds] Fetching user guilds for userID=%s", userID)

	// Step 1. Check cache first
	if cached, ok := guildCache[userID]; ok && time.Now().Before(cached.expiry) {
		utils.LogInfo("[GetUserGuilds] Cache hit for userID=%s", userID)
		c.JSON(http.StatusOK, gin.H{"guilds": cached.guilds})
		return
	}

	// Step 2. Per-user lock to prevent concurrent Discord requests
	lockIface, _ := guildFetchLock.LoadOrStore(userID, &sync.Mutex{})
	lock := lockIface.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	// Step 3. Re-check cache after acquiring lock
	if cached, ok := guildCache[userID]; ok && time.Now().Before(cached.expiry) {
		utils.LogInfo("[GetUserGuilds] Cache re-check hit for userID=%s", userID)
		c.JSON(http.StatusOK, gin.H{"guilds": cached.guilds})
		return
	}

	// Step 4. Fetch user's account from MongoDB
	collection := db.GetCollection("accounts")
	var account models.Account
	if err := collection.FindOne(c, bson.M{"discord_id": userID}).Decode(&account); err != nil {
		utils.LogError("[GetUserGuilds] Account not found for userID=%s: %v", userID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
		return
	}

	// Step 5. Decrypt Discord access token
	accessToken, err := utils.Decrypt(account.Discord.AccessToken, cfg.EncryptionKey)
	if err != nil {
		utils.LogError("[GetUserGuilds] Failed to decrypt Discord access token for userID=%s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt access token"})
		return
	}

	// Step 6. Check token expiry (optional auto-refresh could go here)
	if time.Now().After(account.Discord.ExpiresAt) {
		utils.LogWarn("[GetUserGuilds] Discord access token expired for userID=%s", userID)
		// TODO: Implement auto-refresh using refresh_token
		c.JSON(http.StatusUnauthorized, gin.H{"error": "discord token expired"})
		return
	}

	// Step 7. Fetch from Discord API
	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		utils.LogError("[GetUserGuilds] Failed to reach Discord API for userID=%s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch guilds"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		utils.LogWarn("[GetUserGuilds] Rate limited by Discord for userID=%s", userID)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limited by Discord"})
		return
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		utils.LogError("[GetUserGuilds] Discord API returned %d for userID=%s: %s", resp.StatusCode, userID, string(body))
		c.JSON(resp.StatusCode, gin.H{"error": "discord API error"})
		return
	}

	// Step 8. Decode and filter guilds
	var guilds []models.DiscordGuild
	if err := json.NewDecoder(resp.Body).Decode(&guilds); err != nil {
		utils.LogError("[GetUserGuilds] Failed to decode guild list for userID=%s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode guild list"})
		return
	}

	filtered := filterOwnedGuilds(guilds)
	utils.LogInfo("[GetUserGuilds] Fetched %d guilds (filtered %d) for userID=%s", len(guilds), len(filtered), userID)

	// Step 9. Cache results for 5 minutes
	guildCache[userID] = cachedGuilds{
		guilds: filtered,
		expiry: time.Now().Add(5 * time.Minute),
	}

	utils.LogSuccess("[GetUserGuilds] Guilds successfully cached for userID=%s", userID)
	c.JSON(http.StatusOK, gin.H{"guilds": filtered})
}

func LinkGuild(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)
	claims := c.MustGet("claims").(*utils.JWTClaims)
	userID := claims.UserID
	guildID := c.Param("id")

	var request models.GuildLinkRequest
	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	validate := validator.New()
	if err := validate.Struct(request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("validation failed: %s", err)})
		return
	}

	accountsCollection := db.GetCollection("accounts")
	guildsCollection := db.GetCollection("guilds")

	var account models.Account
	if err := accountsCollection.FindOne(c, bson.M{"discord_id": userID}).Decode(&account); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "account not found"})
		return
	}

	if account.Nitrado == nil || account.Nitrado.AccessToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no nitrado account linked"})
		return
	}

	var ownedGuilds []models.DiscordGuild
	guildCacheMu.RLock()
	cached, found := guildCache[userID]
	guildCacheMu.RUnlock()

	if found && time.Now().Before(cached.expiry) {
		ownedGuilds = cached.guilds
	} else {
		guildsResp, err := FetchAndCacheUserGuilds(cfg, &account)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch Discord guilds"})
			return
		}
		ownedGuilds = guildsResp
	}

	isOwner := false
	for _, g := range ownedGuilds {
		if g.ID == guildID {
			isOwner = g.Owner
			break
		}
	}
	if !isOwner {
		c.JSON(http.StatusForbidden, gin.H{"error": "you must own the guild to link it"})
		return
	}

	mission := ""
	if fetchedMission, err := fetchNitradoMission(cfg, &account, request.NitradoServerID); err == nil {
		mission = fetchedMission
	} else {
		utils.LogWarn("[LinkGuild] Failed to fetch mission for server %d: %v", request.NitradoServerID, err)
	}

	now := time.Now()

	var existingGuild models.GuildConfig
	err := guildsCollection.FindOne(c, bson.M{"server_id": guildID}).Decode(&existingGuild)
	if err != nil && err != mongo.ErrNoDocuments {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check existing guild config"})
		return
	}

	if err == nil {
		if existingGuild.Nitrado != nil && existingGuild.Nitrado.ServerID != 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "guild already linked"})
			return
		}

		update := bson.M{
			"$set": bson.M{
				"owner_id":          userID,
				"nitrado.server_id": request.NitradoServerID,
				"nitrado.mission":   mission,
				"updated_at":        now,
			},
		}

		if _, err := guildsCollection.UpdateOne(c, bson.M{"server_id": guildID}, update); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to relink guild config"})
			return
		}

		existingGuild.OwnerID = userID
		existingGuild.Nitrado = &models.NitradoConfig{
			ServerID: request.NitradoServerID,
			Mission:  mission,
		}
		existingGuild.UpdatedAt = now

		_, _ = accountsCollection.UpdateOne(
			c,
			bson.M{"discord_id": userID},
			bson.M{"$set": bson.M{"updated_at": now}},
		)

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"guild":   existingGuild,
		})
		return
	}

	instanceLimit := account.InstanceAddons.CalculateLimit()
	existingCount, _ := guildsCollection.CountDocuments(c, bson.M{
		"owner_id":          userID,
		"nitrado.server_id": bson.M{"$exists": true, "$nin": []any{"", nil, 0}},
	})

	if uint8(existingCount) >= instanceLimit {
		c.JSON(http.StatusForbidden, gin.H{"error": "instance limit reached"})
		return
	}

	guildAttributes := models.GetDefaultConfig(guildID, userID)

	guildConfig := models.GuildConfig{
		OwnerID: userID,
		GuildID: guildID,
		Active:  false,
		Server:  guildAttributes,
		Nitrado: &models.NitradoConfig{
			ServerID: request.NitradoServerID,
			Mission:  mission,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if _, err := guildsCollection.InsertOne(c, guildConfig); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save guild config"})
		return
	}

	// optional now, since Me derives it anyway
	// _, _ = accountsCollection.UpdateOne(
	// 	c,
	// 	bson.M{"discord_id": userID},
	// 	bson.M{"$set": bson.M{"updated_at": now}},
	// )

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"guild":   guildConfig,
	})
}

func UpdateGuildConfig(c *gin.Context) {
	guildID := c.Param("id")
	utils.LogInfo("Updating guild configuration for guildID=%s", guildID)

	collection := db.GetCollection("guilds")
	validate := validator.New()

	var existing models.GuildConfig
	err := collection.FindOne(context.TODO(), bson.M{"server.server_id": guildID}).Decode(&existing)
	if err == mongo.ErrNoDocuments {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Guild not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to load guild"})
		return
	}

	var incoming map[string]any
	if err := c.BindJSON(&incoming); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	currentBytes, _ := json.Marshal(existing.Server)
	currentMap := map[string]any{}
	_ = json.Unmarshal(currentBytes, &currentMap)

	for k, v := range incoming {
		currentMap[k] = v
	}

	mergedBytes, _ := json.Marshal(currentMap)

	var merged models.GuildAttributes
	if err := json.Unmarshal(mergedBytes, &merged); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config payload"})
		return
	}

	if err := validate.Struct(merged); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("validation failed: %s", err),
		})
		return
	}

	_, err = collection.UpdateOne(
		context.TODO(),
		bson.M{"server.server_id": guildID},
		bson.M{
			"$set": bson.M{
				"server":     merged,
				"updated_at": time.Now(),
			},
		},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to update configuration",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Guild configuration updated successfully",
		"server":  merged,
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

func FetchAndCacheUserGuilds(cfg *config.Config, account *models.Account) ([]models.DiscordGuild, error) {
	token, err := utils.Decrypt(account.Discord.AccessToken, cfg.EncryptionKey)
	if err != nil {
		utils.LogError("[fetchAndCacheUserGuilds] Failed to decrypt token for userID=%s: %v", account.DiscordID, err)
		return nil, err
	}

	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		utils.LogError("[fetchAndCacheUserGuilds] Discord API request failed for userID=%s: %v", account.DiscordID, err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		utils.LogError("[fetchAndCacheUserGuilds] Discord API returned %d for userID=%s: %s", resp.StatusCode, account.DiscordID, string(body))
		return nil, err
	}

	var guilds []models.DiscordGuild
	if err := json.NewDecoder(resp.Body).Decode(&guilds); err != nil {
		utils.LogError("[fetchAndCacheUserGuilds] Failed to decode guild list for userID=%s: %v", account.DiscordID, err)
		return nil, err
	}

	filtered := filterOwnedGuilds(guilds)

	guildCacheMu.Lock()
	guildCache[account.DiscordID] = cachedGuilds{
		guilds: filtered,
		expiry: time.Now().Add(5 * time.Minute),
	}
	guildCacheMu.Unlock()

	utils.LogSuccess("[fetchAndCacheUserGuilds] Cached %d owned guilds for userID=%s", len(filtered), account.DiscordID)
	return filtered, nil
}

func GetLinkedGuilds(c *gin.Context) {
	claims := c.MustGet("claims").(*utils.JWTClaims)
	userID := claims.UserID

	accountsCollection := db.GetCollection("accounts")
	guildsCollection := db.GetCollection("guilds")

	var account models.Account
	if err := accountsCollection.FindOne(c, bson.M{"discord_id": userID}).Decode(&account); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "account not found"})
		return
	}

	if account.Nitrado == nil || account.Nitrado.AccessToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no nitrado account linked"})
		return
	}

	cursor, err := guildsCollection.Find(c, gin.H{
		"owner_id":          userID,
		"nitrado.server_id": bson.M{"$exists": true},
	})
	if err != nil {
		utils.LogError("[GetLinkedGuilds] Error fetching linked guilds: ", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch linked guilds"})
		return
	}
	defer cursor.Close(c)

	var linkedGuilds []models.GuildConfig
	if err := cursor.All(c, &linkedGuilds); err != nil {
		utils.LogError("[GetLinkedGuilds] Error decoding linked guild results")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode linked guild results"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "guilds": linkedGuilds})
}

func fetchNitradoMission(cfg *config.Config, account *models.Account, serverID int64) (string, error) {
	if account.Nitrado == nil || account.Nitrado.AccessToken == "" {
		return "", fmt.Errorf("no nitrado account linked")
	}

	token, err := EnsureValidNitradoToken(account, cfg)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.nitrado.net/services/%d/gameservers", serverID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("nitrado api returned %d: %s", resp.StatusCode, string(body))
	}

	var raw struct {
		Data struct {
			Gameserver struct {
				Settings struct {
					Config struct {
						Mission string `json:"mission"`
					} `json:"config"`
				} `json:"settings"`
			} `json:"gameserver"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return "", err
	}

	return raw.Data.Gameserver.Settings.Config.Mission, nil
}

type ReadinessCheck struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	OK    bool   `json:"ok"`
}

func buildGuildReadiness(config models.GuildConfig) []ReadinessCheck {
	server := config.Server

	return []ReadinessCheck{
		{Key: "nitrado_linked", Label: "Nitrado linked", OK: config.Nitrado != nil && config.Nitrado.ServerID != 0},
		{Key: "server_name", Label: "Server name set", OK: server.ServerName != ""},
		{Key: "killfeed_channel", Label: "Killfeed channel set", OK: server.KillfeedChannel != ""},
		{Key: "connection_logs_channel", Label: "Connection logs channel set", OK: server.ConnectionLogsChannel != ""},
		// {
		// 	Key:   "welcome_channel",
		// 	Label: "Welcome channel set",
		// 	Ready: !welcomeEnabled || strings.TrimSpace(guild.WelcomeChannel) != "",
		// },
		{Key: "linked_gamertag_role", Label: "Linked gamertag role set", OK: server.LinkedGamertagRole != ""},
	}
}

func GetGuildReadiness(c *gin.Context) {
	guildID := c.Param("id")
	collection := db.GetCollection("guilds")

	var config models.GuildConfig
	err := collection.FindOne(context.TODO(), bson.M{"server.server_id": guildID}).Decode(&config)
	if err == mongo.ErrNoDocuments {
		c.JSON(http.StatusNotFound, gin.H{"error": "guild not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	checks := buildGuildReadiness(config)
	ready := true
	for _, check := range checks {
		if !check.OK {
			ready = false
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"guild_id": guildID,
		"active":   config.Active,
		"ready":    ready,
		"checks":   checks,
	})
}

func ActivateGuild(c *gin.Context) {
	guildID := c.Param("id")
	collection := db.GetCollection("guilds")

	var config models.GuildConfig
	err := collection.FindOne(context.TODO(), bson.M{"server.server_id": guildID}).Decode(&config)
	if err == mongo.ErrNoDocuments {
		c.JSON(http.StatusNotFound, gin.H{"error": "guild not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	checks := buildGuildReadiness(config)
	for _, check := range checks {
		if !check.OK {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":  "guild is not ready to activate",
				"checks": checks,
			})
			return
		}
	}

	_, err = collection.UpdateOne(
		context.TODO(),
		bson.M{"server.server_id": guildID},
		bson.M{
			"$set": bson.M{
				"active":     true,
				"updated_at": time.Now(),
			},
		},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to activate guild"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "guild activated",
	})
}

func DeactivateGuild(c *gin.Context) {
	guildID := c.Param("id")
	collection := db.GetCollection("guilds")

	_, err := collection.UpdateOne(
		context.TODO(),
		bson.M{"server.server_id": guildID},
		bson.M{
			"$set": bson.M{
				"active":     false,
				"updated_at": time.Now(),
			},
		},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to deactivate guild"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "guild deactivated",
	})
}

func UnlinkGuild(c *gin.Context) {
	claims := c.MustGet("claims").(*utils.JWTClaims)
	userID := claims.UserID
	guildID := c.Param("id")

	guildsCollection := db.GetCollection("guilds")
	accountsCollection := db.GetCollection("accounts")

	filter := bson.M{
		"owner_id":         userID,
		"server.server_id": guildID,
	}

	update := bson.M{
		"$set": bson.M{
			"active":     false,
			"updated_at": time.Now(),
		},
		"$unset": bson.M{
			"nitrado": "",
		},
	}

	res, err := guildsCollection.UpdateOne(c, filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to unlink guild"})
		return
	}

	if res.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "guild not found"})
		return
	}

	remainingCount, err := guildsCollection.CountDocuments(c, bson.M{
		"owner_id":          userID,
		"nitrado.server_id": bson.M{"$exists": true},
	})
	if err == nil {
		_, _ = accountsCollection.UpdateOne(
			c,
			bson.M{"discord_id": userID},
			bson.M{
				"$set": bson.M{
					"used_instances": remainingCount,
					"updated_at":     time.Now(),
				},
			},
		)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "guild unlinked successfully",
	})
}
