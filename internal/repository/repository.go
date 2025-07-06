package repository

import (
	"auth-service/models"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RepositoryI interface {
	SaveRefreshToken(ctx context.Context, token models.RefreshToken) error
	FindRefreshTokenByPairID(ctx context.Context, userID, pairID string) (models.RefreshToken, error)
	RevokeRefreshTokenByPairID(ctx context.Context, userID, pairID string) error
}

type Repository struct {
	conn *pgxpool.Pool
}

func NewRepository(conn *pgxpool.Pool) RepositoryI {
	return &Repository{
		conn: conn,
	}
}
