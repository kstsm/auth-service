package repository

import (
	"auth-service/models"
	"context"
	"fmt"
)

const (
	queryFindRefreshToken = `
		SELECT id, user_id, token_hash, token_pair_id, user_agent, ip, revoked, created_at
		FROM refresh_tokens
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 1`

	queryFindRefreshTokenByPairID = `
		SELECT id, user_id, token_hash, token_pair_id, user_agent, ip, revoked, created_at
		FROM refresh_tokens
		WHERE user_id = $1
		  AND token_pair_id = $2
		  AND revoked = false`

	querySaeRefreshToken = `
		INSERT INTO refresh_tokens (user_id, token_hash, token_pair_id, user_agent, ip) 
		VALUES ($1, $2, $3, $4, $5)`
)

func (r Repository) SaveRefreshToken(ctx context.Context, token models.RefreshToken) error {
	_, err := r.conn.Exec(ctx, querySaeRefreshToken,
		token.UserID, token.TokenHash, token.TokenPairID, token.UserAgent, token.IP)
	if err != nil {
		return fmt.Errorf("r.conn.Exec: %w", err)
	}

	return nil
}

func (r Repository) FindRefreshToken(ctx context.Context, userID string) (models.RefreshToken, error) {
	var token models.RefreshToken

	row := r.conn.QueryRow(ctx, queryFindRefreshToken, userID)
	err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.TokenPairID,
		&token.UserAgent,
		&token.IP,
		&token.Revoked,
		&token.CreatedAt,
	)
	if err != nil {
		return models.RefreshToken{}, fmt.Errorf("refresh token not found for user %s: %w", userID, err)
	}

	return token, nil
}

func (r Repository) FindRefreshTokenByPairID(ctx context.Context, userID, pairID string) (models.RefreshToken, error) {
	var token models.RefreshToken

	row := r.conn.QueryRow(ctx, queryFindRefreshTokenByPairID, userID, pairID)
	err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.TokenPairID,
		&token.UserAgent,
		&token.IP,
		&token.Revoked,
		&token.CreatedAt,
	)
	if err != nil {
		return models.RefreshToken{}, fmt.Errorf("refresh token not found for user %s with pair_id %s: %w", userID, pairID, err)
	}

	return token, nil
}

func (r Repository) RevokeRefreshToken(ctx context.Context, userID string) error {
	_, err := r.conn.Exec(ctx, `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false`, userID)
	if err != nil {
		return fmt.Errorf("r.conn.Exec: %w", err)
	}

	return nil
}
