package service

import (
	"auth-service/internal/apperrors"
	"auth-service/internal/auth"
	"auth-service/models"
	"context"
	"github.com/gookit/slog"
)

func (s Service) GenerateTokens(ctx context.Context, userID, ip, userAgent string) (models.GetTokensResponse, error) {
	tokenBase64, hash, pairID, err := auth.GenerateRefreshToken()
	if err != nil {
		return models.GetTokensResponse{}, err
	}

	access, err := auth.GenerateAccessToken(userID, ip, userAgent, pairID)
	if err != nil {
		return models.GetTokensResponse{}, err
	}

	refreshToken := models.RefreshToken{
		UserID:      userID,
		TokenHash:   hash,
		UserAgent:   userAgent,
		IP:          ip,
		TokenPairID: pairID,
	}

	if err = s.repo.SaveRefreshToken(ctx, refreshToken); err != nil {
		return models.GetTokensResponse{}, err
	}

	return models.GetTokensResponse{
		Access:  access,
		Refresh: tokenBase64,
	}, nil
}

func (s Service) RefreshTokens(ctx context.Context, userID, access, refresh, userAgent, ip string) (models.GetTokensResponse, error) {
	accessPairID, err := s.validateAccessToken(access, userID)
	if err != nil {
		return models.GetTokensResponse{}, err
	}

	token, err := s.validateRefreshToken(ctx, userID, accessPairID, refresh)
	if err != nil {
		return models.GetTokensResponse{}, err
	}

	if token.UserAgent != userAgent {
		_ = s.repo.RevokeRefreshTokenByPairID(ctx, userID, accessPairID)
		slog.Error("user agent mismatch user is deauthorized")
		return models.GetTokensResponse{}, apperrors.ErrUserDeauthorized
	}

	if ip != token.IP {
		slog.Warn("authorization from new ip", "user_id", userID, "old_ip", token.IP, "new_ip", ip)
	}

	if err = s.repo.RevokeRefreshTokenByPairID(ctx, userID, accessPairID); err != nil {
		return models.GetTokensResponse{}, err
	}

	return s.GenerateTokens(ctx, userID, ip, userAgent)
}

func (s Service) Logout(ctx context.Context, userID, accessToken string) error {
	claims, err := auth.ParseAndValidateToken(accessToken)
	if err != nil {
		return err
	}

	pairID, ok := claims["token_pair_id"].(string)
	if !ok || pairID == "" {
		return apperrors.ErrInvalidToken
	}

	return s.repo.RevokeRefreshTokenByPairID(ctx, userID, pairID)
}
