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

// Redirects user to Discord login
func DiscordLogin(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)

	utils.LogInfo("Initiating Discord OAuth login redirect")

	params := url.Values{}
	params.Add("client_id", cfg.ClientID)
	params.Add("redirect_uri", cfg.RedirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "identify guilds email")

	redirectURL := fmt.Sprintf("https://discord.com/api/oauth2/authorize?%s", params.Encode())
	utils.LogSuccess("Redirecting user to Discord OAuth: %s", redirectURL)
	c.Redirect(http.StatusFound, redirectURL)
}

// Handles Discord callback, exchanges code for token, issues JWT
func DiscordCallback(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)
	code := c.Query("code")

	utils.LogInfo("Handling Discord callback")

	if code == "" {
		utils.LogError("[DiscordCallback] Missing authorization code in query")
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	utils.LogInfo("[DiscordCallback] Exchanging authorization code for access token")

	form := url.Values{}
	form.Add("client_id", cfg.ClientID)
	form.Add("client_secret", cfg.ClientSecret)
	form.Add("grant_type", "authorization_code")
	form.Add("code", code)
	form.Add("redirect_uri", cfg.RedirectURI)
	form.Add("scope", "identify guilds email")

	req, err := http.NewRequest("POST", "https://discord.com/api/oauth2/token", bytes.NewBufferString(form.Encode()))
	if err != nil {
		utils.LogError("[DiscordCallback] Failed to create token request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		utils.LogError("[DiscordCallback] Failed to reach Discord API: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reach discord"})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		utils.LogError("[DiscordCallback] Discord token exchange failed: status=%d, body=%s", resp.StatusCode, string(body))
		c.JSON(resp.StatusCode, gin.H{"error": "discord token exchange failed", "body": string(body)})
		return
	}

	utils.LogSuccess("[DiscordCallback] Successfully exchanged code for token")

	var token models.DiscordTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		utils.LogError("[DiscordCallback] Invalid token response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid token response"})
		return
	}

	// Fetch user info
	user, err := fetchDiscordUser(token.AccessToken)
	if err != nil {
		utils.LogError("[DiscordCallback] Failed to fetch Discord user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
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

	// Determine managed guilds
	var managedGuilds []string
	const ManageGuildPerm = 1 << 5 // 0x20 (bit 5)
	for _, g := range guilds {
		if g.Owner || (g.Permissions&ManageGuildPerm) != 0 {
			managedGuilds = append(managedGuilds, g.ID)
		}
	}

	now := time.Now()
	collection := db.GetCollection("accounts")
	filter := bson.M{"discord_id": user.ID}
	update := bson.M{
		"$set": bson.M{
			"username":   user.Username,
			"email":      user.Email,
			"avatar":     user.Avatar,
			"last_login": now,
			"updated_at": now,
		},
		"$setOnInsert": bson.M{"created_at": now},
	}
	opts := options.Update().SetUpsert(true)

	if _, err := collection.UpdateOne(c, filter, update, opts); err != nil {
		utils.LogError("[DiscordCallback] Failed to upsert account for user %s: %v", user.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upsert account"})
		return
	}

	utils.LogSuccess("[DiscordCallback] Account record upserted for user %s", user.ID)

	// Create JWT
	claims := utils.JWTClaims{
		UserID:      user.ID,
		Username:    user.Username,
		AccessToken: token.AccessToken,
		Guilds:      managedGuilds,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(4 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	jwtToken, err := utils.GenerateJWT(cfg.JWTSecret, claims)
	if err != nil {
		utils.LogError("[DiscordCallback] Failed to issue JWT for user %s: %v", user.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue jwt"})
		return
	}

	utils.LogSuccess("[DiscordCallback] JWT successfully generated for user %s", user.ID)

	// Redirect or return token depending on frontend setup
	origin := c.Request.Header.Get("Origin")
	frontendURL := cfg.FrontendURL[0]
	for _, allowed := range cfg.FrontendURL {
		if allowed == origin {
			frontendURL = origin
			break
		}
	}

	redirectURL := fmt.Sprintf("%s/login?token=%s", frontendURL, jwtToken)
	utils.LogInfo("[DiscordCallback] Redirecting user %s to frontend: %s", user.ID, redirectURL)
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func Me(c *gin.Context) {
	claims, _ := c.Get("claims")
	utils.LogInfo("[Me] Returning authenticated user claims")
	c.JSON(http.StatusOK, gin.H{"user": claims})
}

// Fetch Discord user info
func fetchDiscordUser(accessToken string) (*models.DiscordUser, error) {
	utils.LogInfo("[fetchDiscordUser] Requesting user info from Discord")

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
		utils.LogError("[fetchDiscordUser] Discord API %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("discord api %d: %s", resp.StatusCode, string(body))
	}

	var user models.DiscordUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		utils.LogError("[fetchDiscordUser] Decode error: %v", err)
		return nil, err
	}

	utils.LogSuccess("[fetchDiscordUser] Successfully decoded Discord user %s (%s)", user.Username, user.ID)
	return &user, nil
}

// Fetch Discord guilds list
func fetchDiscordGuilds(accessToken string) ([]models.DiscordGuild, error) {
	utils.LogInfo("[fetchDiscordGuilds] Requesting guild list from Discord")

	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept-Encoding", "gzip")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		utils.LogError("[fetchDiscordGuilds] Request error: %v", err)
		return nil, fmt.Errorf("request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		utils.LogError("[fetchDiscordGuilds] Discord API %d: %s", resp.StatusCode, string(b))
		return nil, fmt.Errorf("discord api %d: %s", resp.StatusCode, string(b))
	}

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			utils.LogError("[fetchDiscordGuilds] Gzip reader error: %v", err)
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	body, _ := io.ReadAll(reader)

	var guilds []models.DiscordGuild
	if err := json.Unmarshal(body, &guilds); err != nil {
		utils.LogError("[fetchDiscordGuilds] Decode error: %v", err)
		return nil, fmt.Errorf("decode error: %w", err)
	}

	utils.LogSuccess("[fetchDiscordGuilds] Successfully decoded %d guilds", len(guilds))
	return guilds, nil
}
