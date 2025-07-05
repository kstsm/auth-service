package service

import (
	"auth-service/internal/repository"
	"auth-service/models"
	"context"
)

type ServiceI interface {
	GetTokens(ctx context.Context, userID, ip, userAgent string) (models.GetTokensResponse, error)
	RefreshTokens(ctx context.Context, userID, access, refresh, ip, userAgent string) (models.GetTokensResponse, error)
	Logout(ctx context.Context, userID string) error
	IsUserAuthorized(ctx context.Context, userID string) (bool, error)
}

type Service struct {
	repo repository.RepositoryI
}

func NewService(repo repository.RepositoryI) *Service {
	return &Service{
		repo: repo,
	}
}
