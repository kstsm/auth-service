package models

import (
	"time"
)

type TokensResponse struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type RefreshRequest struct {
	UserID  string `json:"user_id"`
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
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
