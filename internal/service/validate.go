package service

import (
	"auth-service/internal/apperrors"
	"auth-service/internal/auth"
	"auth-service/models"
	"context"
	"encoding/base64"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func (s Service) validateAccessToken(access, userID string) (string, error) {
	accessClaims, err := auth.ParseAndValidateToken(access)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", apperrors.ErrTokenExpired
		}
		return "", apperrors.ErrInvalidToken
	}

	accessUserID, ok := accessClaims["user_id"].(string)
	if !ok || accessUserID != userID {
		return "", apperrors.ErrInvalidToken
	}

	accessPairID, ok := accessClaims["token_pair_id"].(string)
	if !ok || accessPairID == "" {
		return "", apperrors.ErrInvalidToken
	}

	return accessPairID, nil
}

func (s Service) validateRefreshToken(ctx context.Context, userID, pairID, refresh string) (models.RefreshToken, error) {
	token, err := s.repo.FindRefreshTokenByPairID(ctx, userID, pairID)
	if err != nil {
		return models.RefreshToken{}, apperrors.ErrTokenIsNotFound
	}

	if token.Revoked == true {
		return models.RefreshToken{}, apperrors.ErrTokenRevoked
	}

	decRefresh, err := base64.URLEncoding.DecodeString(refresh)
	if err != nil {
		_ = s.repo.RevokeRefreshTokenByPairID(ctx, userID, pairID)
		return models.RefreshToken{}, apperrors.ErrInvalidToken
	}

	if err = bcrypt.CompareHashAndPassword([]byte(token.TokenHash), decRefresh); err != nil {
		_ = s.repo.RevokeRefreshTokenByPairID(ctx, userID, pairID)
		return models.RefreshToken{}, apperrors.ErrInvalidToken
	}

	return token, nil
}
