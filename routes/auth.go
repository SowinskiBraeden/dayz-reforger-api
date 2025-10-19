package routes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"

	"github.com/gin-gonic/gin"
)

type DiscordTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type DiscordUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	Avatar        string `json:"avatar"`
}

type DiscordGuild struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Icon        string `json:"icon"`
	Owner       bool   `json:"owner"`
	Permissions int64  `json:"permissions,string"`
}

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

	var token DiscordTokenResponse
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
		UserID:   user.ID,
		Username: user.Username,
		Guilds:   managedGuilds,
		Role:     "user",
	}

	jwtToken, err := utils.GenerateJWT(cfg.JWTSecret, claims)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue jwt"})
		return
	}

	// Redirect or return token depending on frontend setup
	// Option 1: Redirect to frontend with token
	redirect := fmt.Sprintf("%s/login?token=%s", cfg.FrontendURL, jwtToken)
	c.Redirect(http.StatusFound, redirect)

	// Option 2 (for API-only testing):
	// c.JSON(200, gin.H{"token": jwtToken})
}

// Returns the current authenticated user (JWT-based)
func Me(c *gin.Context) {
	claims, _ := c.Get("claims")
	c.JSON(http.StatusOK, gin.H{"user": claims})
}

// Helper: Fetch Discord user info
func fetchDiscordUser(accessToken string) (*DiscordUser, error) {
	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user DiscordUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

// Helper: Fetch Discord guilds
func fetchDiscordGuilds(accessToken string) ([]DiscordGuild, error) {
	req, _ := http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
	req.Header.Set("Authorization", "Bearer  "+accessToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var guilds []DiscordGuild
	if err := json.NewDecoder(resp.Body).Decode(&guilds); err != nil {
		return nil, err
	}
	return guilds, nil
}
