package routes

import (
	"net/http"

	"github.com/SowinskiBraeden/dayz-reforger-api/config"
	"github.com/SowinskiBraeden/dayz-reforger-api/db"
	"github.com/SowinskiBraeden/dayz-reforger-api/middleware"
	"github.com/SowinskiBraeden/dayz-reforger-api/models"

	"context"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Register guild routes under /api/guilds
func registerGuildRoutes(api *gin.RouterGroup, cfg *config.Config) {
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
		c.JSON(http.StatusNotFound, gin.H{"error": "guild not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	c.JSON(http.StatusOK, config)
}

func UpdateGuildConfig(c *gin.Context) {
	guildID := c.Param("id")
	var payload models.GuildConfig

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}

	collection := db.GetCollection("guilds")
	filter := bson.M{"server.serverID": guildID}
	update := bson.M{"$set": payload}

	_, err := collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}
