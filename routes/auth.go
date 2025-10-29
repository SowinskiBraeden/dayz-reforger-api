package routes

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/db"
	"github.com/SowinskiBraeden/dayz-reforger-api/models"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/gin-gonic/gin"
)

// Redirect user to Discord login
func DiscordLogin(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)

	utils.LogInfo("Initiating Discord OAuth login redirect")

	params := url.Values{}
	params.Add("client_id", cfg.DiscordClientID)
	params.Add("redirect_uri", cfg.DiscordRedirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "identify guilds email")

	redirectURL := fmt.Sprintf("https://discord.com/api/oauth2/authorize?%s", params.Encode())
	utils.LogSuccess("Redirecting user to Discord OAuth: %s", redirectURL)
	c.Redirect(http.StatusFound, redirectURL)
}

// Handle Discord OAuth callback
func DiscordCallback(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)
	code := c.Query("code")

	if code == "" {
		utils.LogError("[DiscordCallback] Missing authorization code in query")
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	utils.LogInfo("[DiscordCallback] Exchanging code for access token")

	form := url.Values{}
	form.Add("client_id", cfg.DiscordClientID)
	form.Add("client_secret", cfg.DiscordClientSecret)
	form.Add("grant_type", "authorization_code")
	form.Add("code", code)
	form.Add("redirect_uri", cfg.DiscordRedirectURI)

	req, err := http.NewRequest("POST", "https://discord.com/api/oauth2/token", bytes.NewBufferString(form.Encode()))
	if err != nil {
		utils.LogError("[DiscordCallback] Failed to create token request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		utils.LogError("[DiscordCallback] Failed to reach Discord: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "discord request failed"})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		utils.LogError("[DiscordCallback] Discord token exchange failed: %s", string(body))
		c.JSON(http.StatusBadRequest, gin.H{"error": "discord token exchange failed"})
		return
	}

	var token models.DiscordTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		utils.LogError("[DiscordCallback] Invalid token response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid token response"})
		return
	}

	// Fetch user info from Discord
	user, err := fetchDiscordUser(token.AccessToken)
	if err != nil {
		utils.LogError("[DiscordCallback] Failed to fetch Discord user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get discord user"})
		return
	}

	utils.LogInfo("[DiscordCallback] Retrieved user info for %s (%s)", user.Username, user.ID)

	// Fetch guilds from Discord
	guilds, err := fetchDiscordGuilds(token.AccessToken)
	if err != nil {
		utils.LogWarn("[DiscordCallback] Failed to fetch Discord guilds: %v", err)
	} else {
		utils.LogInfo("[DiscordCallback] Retrieved %d guilds for user %s", len(guilds), user.ID)
	}

	var ownedGuilds []string
	for _, g := range guilds {
		if g.Owner || (g.Permissions&0x20) != 0 {
			ownedGuilds = append(ownedGuilds, g.ID)
		}
	}

	utils.LogInfo("[DiscordCallback] Retrieved %d guilds for %s", len(guilds), user.ID)

	// Upsert account record in Mongo
	collection := db.GetCollection("accounts")
	now := time.Now()

	// Encrypt the Discord access token
	encAccess, _ := utils.Encrypt(token.AccessToken, cfg.EncryptionKey)
	encRefresh, _ := utils.Encrypt(token.RefreshToken, cfg.EncryptionKey)

	update := bson.M{
		"$set": bson.M{
			"username":              user.Username,
			"email":                 user.Email,
			"avatar":                user.Avatar,
			"discord.access_token":  encAccess,
			"discord.refresh_token": encRefresh,
			"discord.expires_at":    now.Add(time.Duration(token.ExpiresIn) * time.Second),
			"discord.linked_at":     now,
			"last_login":            now,
			"updated_at":            now,
		},
		"$setOnInsert": bson.M{
			"discord_id": user.ID,
			"created_at": now,
			"subscription": models.Subscription{
				Tier:      "free",
				AutoRenew: false,
				ExpiresAt: nil,
				RenewsAt:  nil,
				UpdatedAt: now,
			},
			"instance_addons": models.InstanceAddon{
				BaseLimit:      1,
				ExtraInstances: 0,
				AutoRenew:      false,
				ExpiresAt:      nil,
				RenewsAt:       nil,
				UpdatedAt:      now,
			},
			"used_instances": 0,
		},
	}

	_, err = collection.UpdateOne(
		c,
		bson.M{"discord_id": user.ID},
		update,
		options.Update().SetUpsert(true),
	)
	if err != nil {
		utils.LogError("[DiscordCallback] Failed to upsert account: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upsert account"})
		return
	}

	utils.LogSuccess("[DiscordCallback] Account successfully upserted for %s", user.ID)

	// Generate minimal JWT
	claims := utils.JWTClaims{
		UserID:   user.ID,
		Username: user.Username,
		Guilds:   ownedGuilds,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(6 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	jwtToken, err := utils.GenerateJWT(cfg.JWTSecret, claims)
	if err != nil {
		utils.LogError("[DiscordCallback] Failed to issue JWT: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "jwt generation failed"})
		return
	}

	utils.LogSuccess("[DiscordCallback] Issued new JWT for user %s", user.ID)

	// Redirect to frontend with token
	origin := c.Request.Header.Get("Origin")
	frontendURL := cfg.FrontendURL[0]
	for _, allowed := range cfg.FrontendURL {
		if allowed == origin {
			frontendURL = origin
			break
		}
	}

	redirectURL := fmt.Sprintf("%s/login?token=%s", frontendURL, jwtToken)
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// Returns full account info (not just JWT claims)
func Me(c *gin.Context) {
	claims := c.MustGet("claims").(*utils.JWTClaims)

	collection := db.GetCollection("accounts")
	var account models.Account

	err := collection.FindOne(c, bson.M{"discord_id": claims.UserID}).Decode(&account)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
		return
	}

	// Strip sensitive tokens before sending to frontend
	if account.Discord.AccessToken != "" {
		account.Discord.AccessToken = ""
		account.Discord.RefreshToken = ""
	}
	if account.Nitrado != nil {
		account.Nitrado.AccessToken = ""
		account.Nitrado.RefreshToken = ""
	}

	account.InstanceAddons.InstanceLimit = account.InstanceAddons.CalculateLimit()

	utils.LogInfo("[Me] Returning full account for %s", claims.UserID)
	c.JSON(http.StatusOK, gin.H{"user": account})
}

// --- Discord API helpers ---
func fetchDiscordUser(accessToken string) (*models.DiscordUser, error) {
	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		utils.LogError("[fetchDiscordUser] Request error: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discord user fetch failed: %s", body)
	}

	var user models.DiscordUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		utils.LogError("[fetchDiscordUser] Decode error: %v", err)
		return nil, err
	}
	return &user, nil
}

// Fetch Discord guilds list
func fetchDiscordGuilds(accessToken string) ([]models.DiscordGuild, error) {
	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept-Encoding", "gzip")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		utils.LogError("[fetchDiscordGuilds] Discord API %d: %s", resp.StatusCode, string(b))
		return nil, fmt.Errorf("discord api %d: %s", resp.StatusCode, string(b))
	}

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, _ := gzip.NewReader(resp.Body)
		defer gz.Close()
		reader = gz
	}

	var guilds []models.DiscordGuild
	if err := json.NewDecoder(reader).Decode(&guilds); err != nil {
		return nil, err
	}
	return guilds, nil
}
