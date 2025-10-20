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
	"github.com/SowinskiBraeden/dayz-reforger-api/models"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"
	"github.com/golang-jwt/jwt/v5"

	"github.com/gin-gonic/gin"
)

// Redirects user to Discord login
func DiscordLogin(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)

	params := url.Values{}
	params.Add("client_id", cfg.ClientID)
	params.Add("redirect_uri", cfg.RedirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "identify guilds email")

	redirectURL := fmt.Sprintf("https://discord.com/api/oauth2/authorize?%s", params.Encode())
	c.Redirect(http.StatusFound, redirectURL)
}

// Handles Discord callback, exchanges code for token, issues JWT
func DiscordCallback(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)
	code := c.Query("code")

	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	form := url.Values{}
	form.Add("client_id", cfg.ClientID)
	form.Add("client_secret", cfg.ClientSecret)
	form.Add("grant_type", "authorization_code")
	form.Add("code", code)
	form.Add("redirect_uri", cfg.RedirectURI)
	form.Add("scope", "identify guilds email")

	req, err := http.NewRequest("POST", "https://discord.com/api/oauth2/token", bytes.NewBufferString(form.Encode()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reach discord"})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		c.JSON(resp.StatusCode, gin.H{"error": "discord token exchange failed", "body": string(body)})
		return
	}

	var token models.DiscordTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid token response"})
		return
	}

	// Fetch user info
	user, err := fetchDiscordUser(token.AccessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	// Fetch guilds from Discord
	guilds, _ := fetchDiscordGuilds(token.AccessToken)

	// Only include guilds the user owns OR has MANAGE_GUILD permission
	var managedGuilds []string
	const ManageGuildPerm = 1 << 5 // 0x20 (bit 5)

	for _, g := range guilds {
		// owner always has full access
		if g.Owner {
			managedGuilds = append(managedGuilds, g.ID)
			continue
		}

		// Convert string permissions to integer
		perms := g.Permissions
		if perms&ManageGuildPerm != 0 {
			managedGuilds = append(managedGuilds, g.ID)
		}
	}

	// Create JWT claims
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue jwt"})
		return
	}

	// Redirect or return token depending on frontend setup
	// Option 1: Redirect to frontend with token
	// Pick first allowed frontend URL (or fallback)
	origin := c.Request.Header.Get("Origin")
	frontendURL := cfg.FrontendURL[0]

	for _, allowed := range cfg.FrontendURL {
		if allowed == origin {
			frontendURL = origin
			break
		}
	}

	redirectURL := fmt.Sprintf("%s/login?token=%s", frontendURL, jwtToken)
	// c.JSON(200, gin.H{"token": jwtToken})
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// Returns the current authenticated user (JWT-based)
func Me(c *gin.Context) {
	claims, _ := c.Get("claims")
	c.JSON(http.StatusOK, gin.H{"user": claims})
}

// Helper: Fetch Discord user info
func fetchDiscordUser(accessToken string) (*models.DiscordUser, error) {
	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user models.DiscordUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func fetchDiscordGuilds(accessToken string) ([]models.DiscordGuild, error) {
	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept-Encoding", "gzip") // optional, Discord supports it

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discord api %d: %s", resp.StatusCode, string(b))
	}

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	body, _ := io.ReadAll(reader)

	var guilds []models.DiscordGuild
	if err := json.Unmarshal(body, &guilds); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}

	return guilds, nil
}
