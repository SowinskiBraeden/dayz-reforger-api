package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/db"
	"github.com/SowinskiBraeden/dayz-reforger-api/models"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

func NitradoLogin(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)

	//JWT from front-end, should be short lived
	token := c.Query("user_token")
	if token == "" {
		utils.LogError("[NitradoLogin] Missing JWT token")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing JWT"})
		return
	}

	// Validate token before redirect
	claims, err := utils.ValidateJWT(token, cfg.JWTSecret)
	if err != nil {
		utils.LogError("[AuthMiddleware] Invalid or expired JWT from %s: %v", c.ClientIP(), err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "invalid or expired JWT",
		})
		return
	}

	// Generate random CSRF value for for nitrado
	state := utils.GenerateRandomString(32)

	utils.TempStoreSet(state, token, 10*time.Minute)

	params := url.Values{}
	params.Add("client_id", cfg.NitradoClientID)
	params.Add("redirect_uri", cfg.NitradoRedirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "service user_info")
	params.Add("state", state)

	redirectURL := fmt.Sprintf("https://oauth.nitrado.net/oauth/v2/auth?%s", params.Encode())
	utils.LogSuccess("Redirecting user %s to Nitrado OAuth: %s", claims.UserID, redirectURL)
	c.Redirect(http.StatusFound, redirectURL)
}

func NitradoCallback(c *gin.Context) {
	cfg := c.MustGet("config").(*config.Config)

	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		utils.LogError("[NitradoCallback] Missing authorization code or state in query")
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code or state"})
		return
	}

	// Retrieve the JWT linked to this state from temporary store
	userToken := utils.TempStoreGet(state)

	if userToken == "" {
		utils.LogError("[NitradoCallback] Invalid or expired OAuth state")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired OAuth state"})
		return
	}

	// Validate user JWT
	claims, err := utils.ValidateJWT(userToken, cfg.JWTSecret)
	if err != nil {
		utils.LogError("[NitradoCallback] Invalid JWT for Nitrado link: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired user token"})
		return
	}

	utils.LogInfo("[NitradoCallback] Exchanging authorization code for Nitrado tokens for user %s", claims.UserID)

	// --- Exchange code for token ---
	form := url.Values{}
	form.Add("client_id", cfg.NitradoClientID)
	form.Add("client_secret", cfg.NitradoClientSecret)
	form.Add("grant_type", "authorization_code")
	form.Add("code", code)

	req, err := http.NewRequest("POST", "https://oauth.nitrado.net/oauth/v2/token", strings.NewReader(form.Encode()))
	if err != nil {
		utils.LogError("[NitradoCallback] Failed to create token request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create token request"})
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		utils.LogError("[NitradoCallback] Failed to contact Nitrado API: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to contact Nitrado API"})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		utils.LogError("[NitradoCallback] Token exchange failed: %s", string(body))
		c.JSON(resp.StatusCode, gin.H{"error": "failed to exchange token"})
		return
	}

	var token models.NitradoTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		utils.LogError("[NitradoCallback] Failed to parse token response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid token response"})
		return
	}

	utils.LogSuccess("[NitradoCallback] Successfully exchanged code for Nitrado tokens")

	// --- Fetch Nitrado user info ---
	user, err := fetchNitradoUser(token.AccessToken)
	if err != nil {
		utils.LogError("[NitradoCallback] Failed to fetch Nitrado user info: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user info"})
		return
	}

	// --- Encrypt and store ---
	encAccess, _ := utils.Encrypt(token.AccessToken, cfg.EncryptionKey)
	encRefresh, _ := utils.Encrypt(token.RefreshToken, cfg.EncryptionKey)

	now := time.Now()
	collection := db.GetCollection("accounts")
	filter := bson.M{"discord_id": claims.UserID}
	update := bson.M{
		"$set": bson.M{
			"nitrado.user_id":       user.Data.User.ID,
			"nitrado.email":         user.Data.User.Email,
			"nitrado.country":       user.Data.User.Profile.Country,
			"nitrado.access_token":  encAccess,
			"nitrado.refresh_token": encRefresh,
			"nitrado.token_type":    token.TokenType,
			"nitrado.scope":         token.Scope,
			"nitrado.expires_at":    now.Add(time.Duration(token.ExpiresIn) * time.Second),
			"nitrado.linked_at":     now,
			"updated_at":            now,
		},
	}

	res, err := collection.UpdateOne(c, filter, update)
	if err != nil || res.MatchedCount == 0 {
		utils.LogError("[NitradoCallback] Failed to update account for user %s: %v", claims.UserID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update account"})
		return
	}

	utils.LogSuccess("[NitradoCallback] Linked Nitrado account for user %s", claims.UserID)

	redirectURL := fmt.Sprintf("%s/dashboard?linked=true", cfg.FrontendURL[0])
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// Fetch Nitrado user info
func fetchNitradoUser(accessToken string) (*models.NitradoUserResponse, error) {
	utils.LogInfo("[fetchNitradoUser] Requesting user info from Nitrado")

	req, _ := http.NewRequest("GET", "https://api.nitrado.net/user", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		utils.LogError("[fetchNitradoUser] Request error: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		utils.LogError("[fetchNitradoUser] Nitrado API %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("nitrado api %d: %s", resp.StatusCode, string(body))
	}

	var user models.NitradoUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		utils.LogError("[fetchNitradoUser] Decode error: %v", err)
		return nil, err
	}

	utils.LogSuccess("[fetchNitradoUser] Successfully decoded Nitrado user %s (%s)", user.Data.User.Username, user.Data.User.ID)
	return &user, nil
}

func EnsureValidNitradoToken(acc *models.Account, cfg *config.Config) (string, error) {
	if time.Now().Before(acc.Nitrado.ExpiresAt) {
		decryptedToken, _ := utils.Decrypt(acc.Nitrado.AccessToken, cfg.EncryptionKey)
		return decryptedToken, nil
	}

	form := url.Values{}
	form.Add("client_id", cfg.NitradoClientID)
	form.Add("client_secret", cfg.NitradoClientSecret)
	form.Add("grant_type", "refresh_token")
	form.Add("refresh_token", acc.Nitrado.RefreshToken)

	req, err := http.NewRequest("POST", "https://oauth.nitrado.net/oauth/v2/token", bytes.NewBufferString(form.Encode()))
	if err != nil {
		utils.LogError("[EnsureValidNitradoToken] Failed to create token request: %v", err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		utils.LogError("[EnsureValidNitradoToken] Failed to reach Nitrado API: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", errors.New(string(body))
	}

	utils.LogSuccess("[EnsureValidNitradoToken] Successfully refreshed token")

	var token models.NitradoTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		utils.LogError("[EnsureValidNitradoToken] Invalid token response: %v", err)
		return "", err
	}

	// re-encrypt + save
	encryptedAccessToken, _ := utils.Encrypt(token.AccessToken, cfg.EncryptionKey)
	encryptedRefreshToken, _ := utils.Encrypt(token.RefreshToken, cfg.EncryptionKey)

	acc.Nitrado.AccessToken = encryptedAccessToken
	acc.Nitrado.RefreshToken = encryptedRefreshToken
	acc.Nitrado.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	acc.UpdatedAt = time.Now()

	// update account
	now := time.Now()
	collection := db.GetCollection("accounts")
	filter := bson.M{"discord_id": acc.DiscordID}
	update := bson.M{
		"$set": bson.M{
			"nitrado.access_token":  encryptedAccessToken,
			"nitrado.refresh_token": encryptedRefreshToken,
			"nitrado.token_type":    token.TokenType,
			"nitrado.expires_at":    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
			"nitrado.scope":         token.Scope,
			"updated_at":            now,
		},
	}

	res, err := collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		utils.LogError("[EnsureValidNitradoToken] Failed to add nitrado credentials to account")
		return "", err
	}

	if res.MatchedCount == 0 {
		utils.LogError("[EnsureValidNitradoToken] Account not found - could not insert nitrado credentials")
		return "", errors.New("could not find account to update")
	}

	return token.AccessToken, nil
}
