package models

type DiscordTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint32 `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type DiscordUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	Discriminator string `json:"discriminator"`
	Avatar        string `json:"avatar"`
}

type DiscordGuild struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Icon           string   `json:"icon"`
	Owner          bool     `json:"owner"`
	Permissions    uint64   `json:"permissions"`
	PermissionsNew string   `json:"permissions_new"`
	Features       []string `json:"features"`
}

type DiscordChannel struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     int    `json:"type"`
	ParentID string `json:"parent_id,omitempty"`
	Position int    `json:"position"`
}

type DiscordRole struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	Description    *string            `json:"description"`
	Permissions    int64              `json:"permissions"`
	PermissionsNew string             `json:"permissions_new"`
	Position       int                `json:"position"`
	Color          int                `json:"color"`
	Colors         *DiscordRoleColors `json:"colors"`
	Hoist          bool               `json:"hoist"`
	Managed        bool               `json:"managed"`
	Mentionable    bool               `json:"mentionable"`
	Icon           *string            `json:"icon"`
	UnicodeEmoji   *string            `json:"unicode_emoji"`
	Tags           map[string]any     `json:"tags"`
	Flags          int                `json:"flags"`
}

type DiscordRoleColors struct {
	PrimaryColor   int  `json:"primary_color"`
	SecondaryColor *int `json:"secondary_color"`
	TertiaryColor  *int `json:"tertiary_color"`
}
