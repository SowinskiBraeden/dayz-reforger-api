package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Alarm struct {
}

type UAV struct {
}

type Event struct {
}

type FactionArmband struct {
	Faction string `bson:"faction" json:"faction"`
	Armband string `bson:"armband" json:"armband"`
}

type GuildAttributes struct {
	ServerID              string                    `bson:"serverID" json:"serverID"`
	LastLog               string                    `bson:"lastLog" json:"lastLog"`
	ServerName            string                    `bson:"serverName" json:"serverName"`
	AutoRestart           bool                      `bson:"autoRestart" json:"autoRestart"`
	ShowKillfeedCoords    bool                      `bson:"showKillfeedCoords" json:"showKillfeedCoords"`
	ShowKillfeedWeapon    bool                      `bson:"showKillfeedWeapon" json:"showKillfeedWeapon"`
	PurchaseUAV           bool                      `bson:"purchaseUAV" json:"purchaseUAV"`
	PurchaseEMP           bool                      `bson:"purchaseEMP" json:"purchaseEMP"`
	AllowedChannels       []string                  `bson:"allowedChannels" json:"allowedChannels"`
	KillfeedChannel       string                    `bson:"killfeedChannel" json:"killfeedChannel"`
	ConnectionLogsChannel string                    `bson:"connectionLogsChannel" json:"connectionLogsChannel"`
	ActivePlayersChannel  string                    `bson:"activePlayersChannel" json:"activePlayersChannel"`
	WelcomeChannel        string                    `bson:"welcomeChannel" json:"welcomeChannel"`
	FactionArmbands       map[string]FactionArmband `bson:"factionArmbands" json:"factionArmbands"`
	UsedArmbands          []string                  `bson:"usedArmbands" json:"usedArmbands"`
	ExcludedRoles         []string                  `bson:"excludedRoles" json:"excludedRoles"`
	BotAdminRoles         []string                  `bson:"botAdminRoles" json:"botAdminRoles"`
	Alarms                []Alarm                   `bson:"alarms" json:"alarms"`
	Events                []Event                   `bson:"events" json:"events"`
	Uavs                  []UAV                     `bson:"uavs" json:"uavs"`
	IncomeRoles           []string                  `bson:"incomeRoles" json:"incomeRoles"`
	IncomeLimiter         float32                   `bson:"incomeLimiter" json:"incomeLimiter"`
	StartingBalance       float32                   `bson:"startingBalance" json:"startingBalance"`
	UavPrice              float32                   `bson:"uavPrice" json:"uavPrice"`
	EmpPrice              float32                   `bson:"empPrice" json:"empPrice"`
	LinkedGamertagRole    string                    `bson:"linkedGamertagRole" json:"linkedGamertagRole"`
	MemberRole            string                    `bson:"memberRole" json:"memberRole"`
	AdminRole             string                    `bson:"adminRole" json:"adminRole"`
	CombatLogTimer        int                       `bson:"combatLogTimer" json:"combatLogTimer"`
}

type GuildConfig struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Server    GuildAttributes    `bson:"server" json:"server"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}
