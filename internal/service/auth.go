package service

import (
	"auth-service/internal/apperrors"
	"auth-service/internal/auth"
	"auth-service/internal/utils"
	"auth-service/models"
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/gookit/slog"
)

func (s Service) GenerateTokens(ctx context.Context, userID, ip, userAgent string) (models.TokensResponse, error) {
	pairID := uuid.New().String()

	tokenBase64, hash, err := auth.GenerateRefreshToken()
	if err != nil {
		return models.TokensResponse{}, fmt.Errorf("generate refresh token: %w", err)
	}

	access, err := auth.GenerateAccessToken(userID, ip, userAgent, pairID)
	if err != nil {
		return models.TokensResponse{}, fmt.Errorf("generate access token: %w", err)
	}

	refreshToken := models.RefreshToken{
		UserID:      userID,
		TokenHash:   hash,
		UserAgent:   userAgent,
		IP:          ip,
		TokenPairID: pairID,
	}

	if err = s.repo.SaveRefreshToken(ctx, refreshToken); err != nil {
		return models.TokensResponse{}, fmt.Errorf("save refresh token: %w", err)
	}

	return models.TokensResponse{
		Access:  access,
		Refresh: tokenBase64,
	}, nil
}

func (s Service) RefreshTokens(ctx context.Context, userID, access, refresh, userAgent, ip string) (models.TokensResponse, error) {
	accessPairID, err := s.validateAccessToken(access, userID)
	if err != nil {
		return models.TokensResponse{}, fmt.Errorf("validate access token: %w", err)
	}

	token, err := s.validateRefreshToken(ctx, userID, accessPairID, refresh)
	if err != nil {
		return models.TokensResponse{}, fmt.Errorf("validate refresh token: %w", err)
	}

	if token.UserAgent != userAgent {
		if revokeErr := s.repo.RevokeRefreshTokenByPairID(ctx, userID, accessPairID); revokeErr != nil {
			slog.Error("failed to revoke token after user agent mismatch", "err", revokeErr)
		}
		slog.Error("user agent mismatch, user is deauthorized", "user_id", userID)
		return models.TokensResponse{}, apperrors.ErrUserDeauthorized
	}

	if ip != token.IP {
		slog.Warn("authorization from new ip", "user_id", userID, "old_ip", token.IP, "new_ip", ip)
		utils.NotifyNewIP(userID, token.IP, ip, userAgent)
	}

	if err = s.repo.RevokeRefreshTokenByPairID(ctx, userID, accessPairID); err != nil {
		return models.TokensResponse{}, fmt.Errorf("revoke refresh token by pair id: %w", err)
	}

	tokens, err := s.GenerateTokens(ctx, userID, ip, userAgent)
	if err != nil {
		return models.TokensResponse{}, fmt.Errorf("generate new tokens: %w", err)
	}

	return tokens, nil
}

func (s Service) Logout(ctx context.Context, userID, accessToken string) error {
	claims, err := auth.ParseAndValidateToken(accessToken)
	if err != nil {
		return fmt.Errorf("parse and validate token: %w", err)
	}

	pairID, ok := claims["token_pair_id"].(string)
	if !ok || pairID == "" {
		slog.Warn("missing or invalid token_pair_id in claims", "user_id", userID)
		return apperrors.ErrInvalidToken
	}

	if err = s.repo.RevokeRefreshTokenByPairID(ctx, userID, pairID); err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	return nil
}

func (s Service) ParseAccessTokenClaims(token string) (map[string]interface{}, error) {
	claims, err := auth.ParseAndValidateToken(token)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func (s Service) IsRefreshTokenRevoked(ctx context.Context, userID, pairID string) (bool, error) {
	token, err := s.repo.FindRefreshTokenByPairID(ctx, userID, pairID)
	if err != nil {
		return false, err
	}
	return token.Revoked, nil
}
