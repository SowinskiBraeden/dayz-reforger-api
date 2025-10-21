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
	"time"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/db"
	"github.com/SowinskiBraeden/dayz-reforger-api/models"
	"github.com/SowinskiBraeden/dayz-reforger-api/utils"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

func NitradoLogin(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {

		params := url.Values{}
		params.Add("client_id", cfg.NitradoClientID)
		params.Add("redirect_uri", cfg.NitradoRedirectURI)
		params.Add("response_type", "code")
		params.Add("scope", "service user_info")
		params.Add("state", cfg.FrontendURL[0])

		redirectURL := fmt.Sprintf("https://oauth.nitrado.net/oauth/v2/auth?%s", params.Encode())
		utils.LogSuccess("Redirecting user to Nitrado OAuth: %s", redirectURL)
		c.Redirect(http.StatusFound, redirectURL)
	}
}

func NitradoCallback(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		stateFromURL := c.Query("state")
		stateCookie, _ := c.Cookie("oauth_state")

		if stateFromURL == "" || stateFromURL != stateCookie {
			utils.LogError("[NitradoCallback] Invalid OAuth state, potential malicious activity ")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid OAuth state"})
			return
		}

		code := c.Query("code")
		if code == "" {
			utils.LogError("[NitradoCallback] Missing authorization code in query")
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
			return
		}

		utils.LogInfo("[NitradoCallback] Exchanging authorizatoin code for access token")

		form := url.Values{}
		form.Add("client_id", cfg.NitradoClientID)
		form.Add("client_secret", cfg.NitradoClientSecret)
		form.Add("grant_type", "authorization_code")
		form.Add("code", code)

		req, err := http.NewRequest("POST", "https://oauth.nitrado.net/oauth/v2/token", bytes.NewBufferString(form.Encode()))
		if err != nil {
			utils.LogError("[NitradoCallback] Failed to create token request: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			utils.LogError("[NitradoCallback] Failed to reach Nitrado API: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reach nitrado"})
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			c.JSON(http.StatusBadRequest, gin.H{"error": string(body)})
			return
		}

		utils.LogSuccess("[NitradoCallback] Successfully exchanged code for token")

		var token models.NitradoTokenResponse
		if err := json.Unmarshal(body, &token); err != nil {
			utils.LogError("[NitradoCallback] Invalid token response: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid token response"})
			return
		}

		// Fetch user info
		user, err := fetchNitradoUser(token.AccessToken)
		if err != nil {
			utils.LogError("[NitradoCallback] Failed to fetch Nitrado user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
			return
		}

		claims := c.MustGet("claims").(*utils.JWTClaims)

		encryptedAccessToken, _ := utils.Encrypt(token.AccessToken, cfg.EncryptionKey)
		encryptedRefreshToken, _ := utils.Encrypt(token.RefreshToken, cfg.EncryptionKey)

		now := time.Now()
		collection := db.GetCollection("accounts")
		filter := bson.M{"discord_id": claims.UserID}
		update := bson.M{
			"$set": bson.M{
				"nitrado.user_id":       user.Data.User.ID,
				"nitrado.user_email":    user.Data.User.Email,
				"nitrado.user_country":  user.Data.User.Profile.Country,
				"nitrado.access_token":  encryptedAccessToken,
				"nitrado.refresh_token": encryptedRefreshToken,
				"nitrado.token_type":    token.TokenType,
				"nitrado.expires_at":    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
				"nitrado.scope":         token.Scope,
				"nitrado.linked_at":     now,
				"updated_at":            now,
			},
		}

		res, err := collection.UpdateOne(c, filter, update)
		if err != nil {
			utils.LogError("[NitradoCallback] Failed to add nitrado credentials to account")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add nitrado credentials to account"})
			return
		}

		if res.MatchedCount == 0 {
			utils.LogError("[NitradoCallback] Account not found - could not insert nitrado credentials")
			c.JSON(http.StatusForbidden, gin.H{"error": "account not found - login first"})
			return
		}
		utils.LogSuccess("[NitradoCallback] Account record updated for user %s", claims.UserID)

		c.Redirect(http.StatusFound, cfg.FrontendURL[0]+"/dashboard?linked=nitrado")
	}
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
