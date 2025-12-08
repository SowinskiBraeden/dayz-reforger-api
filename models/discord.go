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
