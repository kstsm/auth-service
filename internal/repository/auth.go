package repository

import (
	"auth-service/internal/apperrors"
	"auth-service/models"
	"context"
	"fmt"
)

func (r Repository) FindRefreshTokenByPairID(ctx context.Context, userID, pairID string) (models.RefreshToken, error) {
	var token models.RefreshToken

	row := r.conn.QueryRow(ctx, queryFindRefreshTokenByPairID, userID, pairID)
	err := row.Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.TokenPairID,
		&token.UserAgent, &token.IP, &token.Revoked, &token.CreatedAt)
	if err != nil {
		return models.RefreshToken{}, fmt.Errorf("refresh token not found for user %s with pair_id %s: %w", userID, pairID, err)
	}

	return token, nil
}

func (r Repository) SaveRefreshToken(ctx context.Context, token models.RefreshToken) error {
	_, err := r.conn.Exec(ctx, querySaveRefreshToken,
		token.UserID, token.TokenHash, token.TokenPairID, token.UserAgent, token.IP)
	if err != nil {
		return fmt.Errorf("r.conn.Exec: %w", err)
	}

	return nil
}

func (r Repository) RevokeRefreshTokenByPairID(ctx context.Context, userID, pairID string) error {
	var revoked bool
	err := r.conn.QueryRow(ctx, `
		SELECT revoked 
		FROM refresh_tokens 
		WHERE user_id = $1 AND token_pair_id = $2`,
		userID, pairID).Scan(&revoked)
	if err != nil {
		return fmt.Errorf("token not found: %w", err)
	}

	if revoked == true {
		return apperrors.ErrAlreadyLoggedOut
	}

	_, err = r.conn.Exec(ctx, `
		UPDATE refresh_tokens 
		SET revoked = true 
		WHERE user_id = $1 AND token_pair_id = $2 AND revoked = false`, userID, pairID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	return nil
}
