package models

type NitradoTokenResponse struct {
	AccessToken  string `bson:"access_token" json:"access_token"`
	RefreshToken string `bson:"refresh_token" json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `bson:"scope" json:"scope"`
}

type NitradoUserResponse struct {
	Status string `json:"status"`
	Data   struct {
		User struct {
			ID       int64  `json:"user_id"`
			Username string `json:"username"`
			Email    string `json:"email"`
			Profile  struct {
				Country string `json:"country"`
			} `json:"profile"`
		} `json:"user"`
	} `json:"data"`
}
