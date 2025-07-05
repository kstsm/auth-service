package service

import (
	"auth-service/config"
	"auth-service/internal/apperrors"
	"auth-service/internal/auth"
	"auth-service/models"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gookit/slog"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

func (s Service) GetTokens(ctx context.Context, userID, ip, userAgent string) (models.GetTokensResponse, error) {
	pairID := uuid.NewString()

	access, err := auth.GenerateAccessToken(userID, ip, userAgent, pairID)
	if err != nil {
		return models.GetTokensResponse{}, fmt.Errorf("generate access token: %w", err)
	}

	hash, refresh, err := auth.GenerateRefreshTokenAndHash()
	if err != nil {
		return models.GetTokensResponse{}, fmt.Errorf("generate refresh token: %w", err)
	}

	refreshToken := models.RefreshToken{
		UserID:      userID,
		TokenHash:   hash,
		UserAgent:   userAgent,
		IP:          ip,
		TokenPairID: pairID,
	}

	if err = s.repo.SaveRefreshToken(ctx, refreshToken); err != nil {
		return models.GetTokensResponse{}, fmt.Errorf("save refresh token: %w", err)
	}

	return models.GetTokensResponse{
		Access:  access,
		Refresh: refresh,
	}, nil
}

func (s Service) RefreshTokens(ctx context.Context, userID, access, refresh, userAgent, ip string) (models.GetTokensResponse, error) {
	accessClaims, err := s.validateAccessToken(access, userID)
	if err != nil {
		slog.Warnf("access token validation failed for user %s: %v", userID, err)
		return models.GetTokensResponse{}, err
	}

	token, err := s.validateRefreshToken(ctx, userID, accessClaims["token_pair_id"].(string), refresh)
	if err != nil {
		slog.Warnf("refresh token validation failed for user %s: %v", userID, err)
		return models.GetTokensResponse{}, err
	}

	if err = s.validateUserAgent(ctx, token, userAgent); err != nil {
		slog.Warnf("user agent validation failed for user %s: %v", userID, err)
		return models.GetTokensResponse{}, err
	}

	s.checkAndNotifyNewIP(userID, token.IP, ip, userAgent)

	slog.Infof("successfully refreshed tokens for user: %s", userID)
	return s.generateNewTokenPair(ctx, userID, ip, userAgent)
}

func (s Service) validateAccessToken(access, userID string) (jwt.MapClaims, error) {
	accessClaims, err := auth.ParseAndValidateToken(access)
	if err != nil {
		/*// Проверяем, является ли ошибка связанной с истечением срока действия
		if jwtErr, ok := err.(*jwt.ValidationError); ok {
			if jwtErr.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, apperrors.ErrTokenExpired
			}
		}*/
		return nil, apperrors.ErrInvalidToken
	}

	accessUserID, ok := accessClaims["user_id"].(string)
	if !ok || accessUserID == "" || accessUserID != userID {
		return nil, apperrors.ErrInvalidToken
	}

	accessPairID, ok := accessClaims["token_pair_id"].(string)
	if !ok || accessPairID == "" {
		return nil, apperrors.ErrInvalidToken
	}

	return accessClaims, nil
}

func (s Service) validateRefreshToken(ctx context.Context, userID, pairID, refresh string) (models.RefreshToken, error) {
	token, err := s.repo.FindRefreshTokenByPairID(ctx, userID, pairID)
	if err != nil {
		return models.RefreshToken{}, apperrors.ErrTokenIsNotFound
	}

	if token.Revoked {
		return models.RefreshToken{}, apperrors.ErrTokenRevoked
	}

	if token.TokenPairID != pairID {
		_ = s.repo.RevokeRefreshToken(ctx, userID)
		return models.RefreshToken{}, apperrors.ErrTokenMismatch
	}

	decRefresh, err := base64.URLEncoding.DecodeString(refresh)
	if err != nil {
		_ = s.repo.RevokeRefreshToken(ctx, userID)
		return models.RefreshToken{}, apperrors.ErrInvalidToken
	}

	if err = bcrypt.CompareHashAndPassword([]byte(token.TokenHash), decRefresh); err != nil {
		_ = s.repo.RevokeRefreshToken(ctx, userID)
		return models.RefreshToken{}, apperrors.ErrInvalidToken
	}

	return token, nil
}

func (s Service) validateUserAgent(ctx context.Context, token models.RefreshToken, userAgent string) error {
	if token.UserAgent != userAgent {
		// Деавторизуем пользователя при изменении User-Agent
		_ = s.repo.RevokeRefreshToken(ctx, token.UserID)
		return apperrors.ErrUserDeauthorized
	}
	return nil
}

func (s Service) checkAndNotifyNewIP(userID, oldIP, newIP, userAgent string) {
	if oldIP != newIP {
		go s.sendNewIPWebhook(userID, oldIP, newIP, userAgent)
	}
}

func (s Service) generateNewTokenPair(ctx context.Context, userID, ip, userAgent string) (models.GetTokensResponse, error) {
	newPairID := uuid.NewString()

	accessNew, err := auth.GenerateAccessToken(userID, ip, userAgent, newPairID)
	if err != nil {
		return models.GetTokensResponse{}, fmt.Errorf("generate access token: %w", err)
	}

	hashNew, refreshNew, err := auth.GenerateRefreshTokenAndHash()
	if err != nil {
		return models.GetTokensResponse{}, fmt.Errorf("generate refresh token: %w", err)
	}

	refreshToken := models.RefreshToken{
		UserID:      userID,
		TokenHash:   hashNew,
		UserAgent:   userAgent,
		IP:          ip,
		TokenPairID: newPairID,
	}

	if err = s.repo.RevokeRefreshToken(ctx, userID); err != nil {
		return models.GetTokensResponse{}, fmt.Errorf("failed to revoke token: %w", err)
	}

	if err = s.repo.SaveRefreshToken(ctx, refreshToken); err != nil {
		return models.GetTokensResponse{}, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return models.GetTokensResponse{
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

func (s Service) sendNewIPWebhook(userID, oldIP, newIP, userAgent string) {
	webhookURL := config.GetConfig().Webhook.URL
	if webhookURL == "" {
		return
	}

	payload := map[string]interface{}{
		"user_id":    userID,
		"old_ip":     oldIP,
		"new_ip":     newIP,
		"user_agent": userAgent,
		"timestamp":  time.Now().Unix(),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		slog.Errorf("failed to marshal webhook payload: %v", err)
		return
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		slog.Errorf("failed to send webhook: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Errorf("webhook returned status: %d", resp.StatusCode)
	}
}
