package service

import (
	"auth-service/internal/repository"
	"auth-service/models"
	"context"
)

type ServiceI interface {
	GenerateTokens(ctx context.Context, userID, ip, userAgent string) (models.TokensResponse, error)
	RefreshTokens(ctx context.Context, userID, access, refresh, userAgent, ip string) (models.TokensResponse, error)
	Logout(ctx context.Context, userID, accessToken string) error
	ParseAccessTokenClaims(token string) (map[string]interface{}, error)
	IsRefreshTokenRevoked(ctx context.Context, userID, pairID string) (bool, error)
}

type Service struct {
	repo repository.RepositoryI
}

func NewService(repo repository.RepositoryI) *Service {
	return &Service{
		repo: repo,
	}
}
