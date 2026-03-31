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

// Attributes can be blank, empty strings, but must be there still
type GuildAttributes struct {
	ServerID               string                    `bson:"server_id"                 json:"server_id"`
	OwnerID                string                    `bson:"owner_id"                  json:"owner_id"`
	LastLog                string                    `bson:"last_log"                  json:"last_log"`
	ServerName             string                    `bson:"server_name"               json:"server_name"`
	AutoRestart            bool                      `bson:"auto_restart"              json:"auto_restart"`
	ShowKillfeedCoords     bool                      `bson:"show_killfeed_coords"      json:"show_killfeed_coords"`
	ShowKillfeedWeaponIcon bool                      `bson:"show_killfeed_weapon_icon" json:"show_killfeed_weapon_icon"`
	EnablePurchaseUAV      bool                      `bson:"enable_purchase_uav"       json:"enable_purchase_uav"`
	EnablePurchaseEMP      bool                      `bson:"enable_purchase_emp"       json:"enable_purchase_emp"`
	AllowedCommandChannels []string                  `bson:"allowed_command_channels"  json:"allowed_command_channels"`
	KillfeedChannel        string                    `bson:"killfeed_channel"          json:"killfeed_channel"`
	ConnectionLogsChannel  string                    `bson:"connection_logs_channel"   json:"connection_logs_channel"`
	BaseBuildLogsChannel   string                    `bson:"base_build_logs_channel"   json:"base_build_logs_channel"`
	ActivePlayersChannel   string                    `bson:"active_players_channel"    json:"active_players_channel"`
	ActivePlayersMessageID string                    `bson:"active_players_message_id" json:"active_players_message_id"`
	WelcomeChannel         string                    `bson:"welcome_channel"           json:"welcome_channel"`
	SendWelcomeMessage     bool                      `bson:"send_welcome_message"      json:"send_welcome_message"`
	WelcomeMessage         string                    `bson:"welcome_message"           json:"welcome_message" validate:"max=250"`
	FactionArmbands        map[string]FactionArmband `bson:"faction_armbands"          json:"faction_armbands"`
	UsedArmbands           []string                  `bson:"used_armbands"             json:"used_armbands"`
	ExcludedRoles          []string                  `bson:"excluded_roles"            json:"excluded_roles"`
	AdminAlertRole         string                    `bson:"admin_alert_role"          json:"admin_alert_role"`
	BotAdminRoles          []string                  `bson:"bot_admin_roles"           json:"bot_admin_roles"`
	WebAdminUserIDs        []string                  `bson:"web_admin_user_ids"        json:"web_admin_user_ids"`
	Alarms                 []Alarm                   `bson:"alarms"                    json:"alarms"`
	Events                 []Event                   `bson:"events"                    json:"events"`
	UAVs                   []UAV                     `bson:"uavs"                      json:"uavs"`
	IncomeRoles            []string                  `bson:"income_roles"              json:"income_roles"`
	IncomeLimitHours       float64                   `bson:"income_limit_hours"        json:"income_limit_hours"        validate:"gte=0.0"`
	StartingBalance        float64                   `bson:"starting_balance"          json:"starting_balance"          validate:"gte=0.0"`
	UAVPrice               float64                   `bson:"uav_price"                 json:"uav_price"                 validate:"gte=0.0"`
	UAVRadiusMeters        uint16                    `bson:"uav_radius_meters"         json:"uav_radius_meters"         validate:"gte=25,lte=7500"`
	EMPPrice               float64                   `bson:"emp_price"                 json:"emp_price"                 validate:"gte=0.0"`
	EMPDurationMinutes     uint8                     `bson:"emp_duration_minutes"      json:"emp_duration_minutes"      validate:"gte=30,lte=120"`
	LinkedGamertagRole     string                    `bson:"linked_gamertag_role"      json:"linked_gamertag_role"`
	MemberRole             string                    `bson:"member_role"               json:"member_role"`
	IssueMemberRole        bool                      `bson:"issue_member_role"         json:"issue_member_role"`
	CombatLogTimerMinutes  uint8                     `bson:"combat_log_timer_limits"   json:"combat_log_timer_minutes"  validate:"gte=0,lte=60"`
}

type GuildConfig struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	OwnerID   string             `bson:"owner_id" json:"owner_id"`
	GuildID   string             `bson:"server_id" json:"server_id"`
	Active    bool               `bson:"active" json:"active"`
	Server    GuildAttributes    `bson:"server" json:"server"`
	Nitrado   *NitradoConfig     `bson:"nitrado,omitempty" json:"nitrado,omitempty"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

type NitradoConfig struct {
	ServerID int64  `bson:"server_id" json:"server_id"`
	Status   string `bson:"status,omitempty" json:"status,omitempty"`
	Mission  string `bson:"mission,omitempty" json:"mission,omitempty"`
}

func GetDefaultConfig(serverID, ownerID string) GuildAttributes {
	return GuildAttributes{
		ServerID:               serverID,
		OwnerID:                ownerID,
		LastLog:                "",
		ServerName:             "",
		AutoRestart:            false,
		ShowKillfeedCoords:     true,
		ShowKillfeedWeaponIcon: true,
		EnablePurchaseUAV:      true,
		EnablePurchaseEMP:      true,
		AllowedCommandChannels: []string{},
		KillfeedChannel:        "",
		ConnectionLogsChannel:  "",
		BaseBuildLogsChannel:   "",
		ActivePlayersChannel:   "",
		WelcomeChannel:         "",
		SendWelcomeMessage:     true,
		WelcomeMessage:         "Welcome to our server!",
		FactionArmbands:        map[string]FactionArmband{},
		UsedArmbands:           []string{},
		ExcludedRoles:          []string{},
		BotAdminRoles:          []string{},
		AdminAlertRole:         "",
		WebAdminUserIDs:        []string{},
		Alarms:                 []Alarm{},
		Events:                 []Event{},
		UAVs:                   []UAV{},
		IncomeRoles:            []string{},
		IncomeLimitHours:       168, // # of hours in 7 days
		StartingBalance:        500.00,
		UAVPrice:               50_000.00,
		UAVRadiusMeters:        250,
		EMPPrice:               250_000.00,
		EMPDurationMinutes:     30,
		LinkedGamertagRole:     "",
		MemberRole:             "",
		IssueMemberRole:        false,
		CombatLogTimerMinutes:  5,
	}
}

type GuildLinkRequest struct {
	NitradoServerID int64 `json:"nitrado_server_id" validate:"required"`
}
