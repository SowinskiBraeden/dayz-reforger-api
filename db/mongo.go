package db

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var database *mongo.Database

// Connect initializes the MongoDB connection and sets the global client
func Connect(uri string, dbName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Client().ApplyURI(uri)
	c, err := mongo.Connect(ctx, opts)
	if err != nil {
		log.Fatalf("MongoDB connection failed: %v", err)
	}

	// Ping the database to verify the connection
	if err := c.Ping(ctx, nil); err != nil {
		log.Fatalf("MongoDB ping failed: %v", err)
	}

	client = c
	database = c.Database(dbName)
	log.Printf("Connected to MongoDB: %s", dbName)
}

// GetDB returns the current database reference
func GetDB() *mongo.Database {
	if database == nil {
		log.Fatal("MongoDB not initialized.")
	}
	return database
}

// GetCollection returns a MongoDB collection handle
func GetCollection(name string) *mongo.Collection {
	return GetDB().Collection(name)
}

// Disconnect cleanly closes the MongoDB connection
func Disconnect() {
	if client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Disconnect(ctx)
		log.Println("Disconnected from MongoDB")
	}
}
