package db

import (
	"context"
	"time"

	"github.com/SowinskiBraeden/dayz-reforger-api/utils"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var database *mongo.Database

func Connect(uri string, dbName string) {
	utils.LogInfo("[MongoDB] Connecting to database: %s", dbName)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Client().ApplyURI(uri)
	c, err := mongo.Connect(ctx, opts)
	if err != nil {
		utils.LogError("[MongoDB] Connection failed: %v", err)
		panic(err)
	}

	// Ping the database to verify the connection
	if err := c.Ping(ctx, nil); err != nil {
		utils.LogError("[MongoDB] Ping failed: %v", err)
		panic(err)
	}

	client = c
	database = c.Database(dbName)
	utils.LogSuccess("[MongoDB] Successfully connected to database: %s", dbName)
}

func GetDB() *mongo.Database {
	if database == nil {
		utils.LogError("[MongoDB] Attempted to access database before initialization")
		panic("MongoDB not initialized")
	}
	return database
}

func GetCollection(name string) *mongo.Collection {
	utils.LogInfo("[MongoDB] Accessing collection: %s", name)
	return GetDB().Collection(name)
}

func Disconnect() {
	if client != nil {
		utils.LogInfo("[MongoDB] Disconnecting from MongoDB")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Disconnect(ctx)
		utils.LogSuccess("[MongoDB] Disconnected from MongoDB successfully")
	} else {
		utils.LogWarn("[MongoDB] Disconnect called but client was nil (already disconnected)")
	}
}
