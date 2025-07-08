package service

import (
	"auth-service/internal/apperrors"
	"auth-service/internal/auth"
	"auth-service/models"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gookit/slog"
	"golang.org/x/crypto/bcrypt"
)

func (s Service) validateAccessToken(access, userID string) (string, error) {
	accessClaims, err := auth.ParseAndValidateToken(access)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", fmt.Errorf("access token expired: %w", apperrors.ErrTokenExpired)
		}
		return "", fmt.Errorf("invalid access token: %w", apperrors.ErrInvalidToken)
	}

	accessUserID, ok := accessClaims["user_id"].(string)
	if !ok || accessUserID != userID {
		return "", fmt.Errorf("access token user_id mismatch or missing: %w", apperrors.ErrInvalidToken)
	}

	accessPairID, ok := accessClaims["token_pair_id"].(string)
	if !ok || accessPairID == "" {
		return "", fmt.Errorf("access token missing token_pair_id: %w", apperrors.ErrInvalidToken)
	}

	return accessPairID, nil
}

func (s Service) validateRefreshToken(ctx context.Context, userID, pairID, refresh string) (models.RefreshToken, error) {
	token, err := s.repo.FindRefreshTokenByPairID(ctx, userID, pairID)
	if err != nil {
		return models.RefreshToken{},
			fmt.Errorf("refresh token not found: %w", apperrors.ErrTokenIsNotFound)
	}

	if token.Revoked {
		return models.RefreshToken{},
			fmt.Errorf("refresh token revoked: %w", apperrors.ErrTokenRevoked)
	}

	decRefresh, err := base64.URLEncoding.DecodeString(refresh)
	if err != nil {
		if revokeErr := s.repo.RevokeRefreshTokenByPairID(ctx, userID, pairID); revokeErr != nil {
			slog.Error("failed to revoke refresh token on decode error")
		}
		return models.RefreshToken{},
			fmt.Errorf("invalid refresh token encoding: %w", apperrors.ErrInvalidToken)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(token.TokenHash), decRefresh); err != nil {
		if revokeErr := s.repo.RevokeRefreshTokenByPairID(ctx, userID, pairID); revokeErr != nil {
			slog.Error("failed to revoke refresh token on hash mismatch")
		}
		return models.RefreshToken{},
			fmt.Errorf("refresh token hash mismatch: %w", apperrors.ErrInvalidToken)
	}

	return token, nil
}
