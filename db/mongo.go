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

	// Force authentication by performing a read on the target DB
	testCollection := c.Database(dbName).Collection("auth_test")
	if err := testCollection.FindOne(ctx, map[string]any{}).Err(); err != nil {
		if err == mongo.ErrNoDocuments {
			// This means we successfully authenticated, just no documents
			utils.LogSuccess("[MongoDB] Authentication succeeded for database: %s", dbName)
		} else {
			utils.LogError("[MongoDB] Authentication failed: %v", err)
			panic(err)
		}
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
