package service

import (
	"auth-service/internal/apperrors"
	"auth-service/internal/auth"
	"auth-service/models"
	"context"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func (s Service) GetTokens(ctx context.Context, userID, ip, userAgent string) (models.TokenResp, error) {
	access, err := auth.GenerateAccessToken(userID, ip)
	if err != nil {
		return models.TokenResp{}, fmt.Errorf("generate access token: %w", err)
	}

	hash, refresh, err := auth.GenerateRefreshToken()
	if err != nil {
		return models.TokenResp{}, fmt.Errorf("generate refresh token: %w", err)
	}

	refreshToken := models.RefreshToken{
		UserID:    userID,
		TokenHash: hash,
		UserAgent: userAgent,
		IP:        ip,
	}

	if err = s.repo.SaveRefreshToken(ctx, refreshToken); err != nil {
		return models.TokenResp{}, fmt.Errorf("save refresh token: %w", err)
	}

	return models.TokenResp{
		Access:  access,
		Refresh: refresh,
	}, nil
}

func (s Service) RefreshTokens(ctx context.Context, userID, refresh, userAgent, ip string) (models.TokenResp, error) {
	token, err := s.repo.FindRefreshToken(ctx, userID)
	if err != nil {
		return models.TokenResp{}, apperrors.ErrInvalidToken
	}

	if token.Revoked == true {
		return models.TokenResp{}, apperrors.ErrInvalidToken
	}

	decRefresh, err := base64.URLEncoding.DecodeString(refresh)
	if err != nil {
		return models.TokenResp{}, fmt.Errorf("invalid refresh token: %w", err)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(token.TokenHash), decRefresh); err != nil {
		err = s.repo.RevokeRefreshToken(ctx, userID)
		if err != nil {
			return models.TokenResp{}, fmt.Errorf("failed to revoke token: %w", err)
		}

		return models.TokenResp{}, apperrors.ErrInvalidToken
	}

	if token.UserAgent != userAgent {
		err = s.repo.RevokeRefreshToken(ctx, userID)
		if err != nil {
			return models.TokenResp{}, fmt.Errorf("failed to revoke token: %w", err)
		}

		return models.TokenResp{}, fmt.Errorf("refresh token doesn't match, user is deauthorized: %w", err)
	}

	if token.IP != ip {
		// TODO: отправить POST на webhook о попытке входа с нового IP
	}

	accessNew, err := auth.GenerateAccessToken(userID, ip)
	if err != nil {
		return models.TokenResp{}, fmt.Errorf("generate access token: %w", err)
	}

	hashNew, refreshNew, err := auth.GenerateRefreshToken()
	if err != nil {
		return models.TokenResp{}, fmt.Errorf("generate refresh token: %w", err)
	}

	refreshToken := models.RefreshToken{
		UserID:    userID,
		TokenHash: hashNew,
		UserAgent: userAgent,
		IP:        ip,
	}

	err = s.repo.RevokeRefreshToken(ctx, userID)
	if err != nil {
		return models.TokenResp{}, fmt.Errorf("failed to revoke token: %w", err)

	}

	err = s.repo.SaveRefreshToken(ctx, refreshToken)
	if err != nil {
		return models.TokenResp{}, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return models.TokenResp{
		Access:  accessNew,
		Refresh: refreshNew,
	}, nil
}

func (s Service) Logout(ctx context.Context, userID string) error {
	return s.repo.RevokeRefreshToken(ctx, userID)
}

func (s Service) IsUserAuthorized(ctx context.Context, userID string) (bool, error) {
	token, err := s.repo.FindRefreshToken(ctx, userID)
	if err != nil || token.Revoked {
		return false, err
	}

	return true, nil
}
