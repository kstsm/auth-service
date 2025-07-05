package models

import "time"

type GetTokensResponse struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type Error struct {
	Message string `json:"message"`
}

type RefreshToken struct {
	ID          int
	UserID      string
	TokenHash   string
	TokenPairID string
	UserAgent   string
	IP          string
	Revoked     bool
	CreatedAt   time.Time
}

type RefreshRequest struct {
	UserID  string `json:"user_id"`
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}
