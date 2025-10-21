package models

type NitradoTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
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
