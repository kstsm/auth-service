package repository

import (
	"auth-service/models"
	"context"
	"fmt"
)

func (r Repository) SaveRefreshToken(ctx context.Context, token models.RefreshToken) error {
	_, err := r.conn.Exec(ctx, `INSERT INTO refresh_tokens (user_id, token_hash, user_agent, ip) VALUES ($1, $2, $3, $4)`,
		token.UserID, token.TokenHash, token.UserAgent, token.IP)

	return err
}

func (r Repository) FindRefreshToken(ctx context.Context, userID string) (models.RefreshToken, error) {
	var token models.RefreshToken

	row := r.conn.QueryRow(ctx, `
		SELECT id, user_id, token_hash, user_agent, ip, revoked, created_at 
		FROM refresh_tokens 
		WHERE user_id = $1 
		ORDER BY created_at DESC LIMIT 1`, userID)
	err := row.Scan(&token.ID, &token.UserID, &token.TokenHash, &token.UserAgent, &token.IP, &token.Revoked, &token.CreatedAt)

	fmt.Println(err)
	return token, err
}

func (r Repository) RevokeRefreshToken(ctx context.Context, userID string) error {
	_, err := r.conn.Exec(ctx, `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false`, userID)

	return err
}
