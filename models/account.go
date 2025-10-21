package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Account struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	DiscordID string             `bson:"discord_id" json:"discord_id"`
	Username  string             `bson:"username" json:"username"`
	Email     string             `bson:"email" json:"email"`
	Avatar    string             `bson:"avatar" json:"avatar"`
	LastLogin time.Time          `bson:"last_login" json:"last_login"`
	Nitrado   *Nitrado           `bson:"nitrado,omitempty" json:"nitrado,omitempty"`

	Subscription   Subscription  `bson:"subscription" json:"subscription"`
	InstanceAddons InstanceAddon `bson:"instance_addons" json:"instance_addons"`

	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

type Nitrado struct {
	UserID  string `bson:"user_id" json:"user_id"`
	Email   string `bson:"email" json:"email"`
	Country string `bson:"country" json:"country"`

	NitradoTokenResponse `bson:",inline"`
	ExpiresAt            time.Time `bson:"expires_at" json:"expires_at"`

	Status  string `bson:"Status" json:"Status"`
	Mission string `bson:"Mission" json:"Mission"`

	LinkedAt  time.Time `bson:"linked_at" json:"linked_at"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

// Determine features access
type Subscription struct {
	Plan      string     `bson:"plan" json:"plan"` // e.g. "free", "pro", "analytics"
	AutoRenew bool       `bson:"auto_renew" json:"auto_renew"`
	ExpiresAt *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	RenewsAt  *time.Time `bson:"renews_at,omitempty" json:"renews_at,omitempty"`
	UpdatedAt time.Time  `bson:"updated_at" json:"updated_at"`
}

// Determines number of instances (guild + nitrado dayz) (1 for free)
type InstanceAddon struct {
	BaseLimit      int        `bson:"base_limit" json:"base_limit"`           // Default limit (1 for free)
	ExtraInstances int        `bson:"extra_instances" json:"extra_instances"` // Purchased add-on instances
	TotalLimit     int        `bson:"total_limit" json:"total_limit"`         // Derived (BaseLimit + ExtraInstances)
	AutoRenew      bool       `bson:"auto_renew" json:"auto_renew"`
	ExpiresAt      *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	RenewsAt       *time.Time `bson:"renews_at,omitempty" json:"renews_at,omitempty"`
	UpdatedAt      time.Time  `bson:"last_updated" json:"last_updated"`
}
