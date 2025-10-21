package models

import (
	"time"
)

type Account struct {
	DiscordID    string            `bson:"discord_id" json:"discord_id"`
	Username     string            `bson:"username" json:"username"`
	Email        string            `bson:"email" json:"email"`
	Avatar       string            `bson:"avatar" json:"avatar"`
	LastLogin    time.Time         `bson:"last_login" json:"last_login"`
	Nitrado      *Nitrado          `bson:"nitrado,omitempty" json:"nitrado,omitempty"`
	Subscription *SubscriptionInfo `bson:"subscription,omitempty" json:"subscription,omitempty"`
	Timestamps   `bson:",inline"`
}

type Nitrado struct {
	UserID      string `bson:"user_id" json:"user_id"`
	Email       string `bson:"email" json:"email"`
	Country     string `bson:"country" json:"country"`
	AccessToken string `bson:"access_token" json:"access_token"`

	Status  string `bson:"Status" json:"Status"`
	Mission string `bson:"Mission" json:"Mission"`

	LinkedAt time.Time `bson:"linked_at" json:"linked_at"`
}

type SubscriptionInfo struct {
	Tier      string    `bson:"tier" json:"tier"` // e.g. "free", "pro", "analytics"
	ExpiresAt time.Time `bson:"expires_at" json:"expires_at"`
}
