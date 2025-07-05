package handler

import (
	"auth-service/internal/apperrors"
	"auth-service/internal/utils"
	"auth-service/models"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/gookit/slog"
	"net/http"
	"strings"
)

func (h Handler) getTokensHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if strings.TrimSpace(userID) == "" {
		slog.Warn("user_id is missing")
		utils.WriteError(w, http.StatusBadRequest, "user_id обязателен")
		return
	}

	if _, err := uuid.Parse(userID); err != nil {
		slog.Warn("user_id invalid GUID format", userID)
		utils.WriteError(w, http.StatusBadRequest, "user_id имеет неверный формат GUID")
		return
	}

	ip := utils.GetIP(r)
	userAgent := r.UserAgent()

	resp, err := h.service.GetTokens(r.Context(), userID, ip, userAgent)
	if err != nil {
		slog.Errorf("internal error: %v", err)
		utils.WriteError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
		return
	}

	utils.SendJSON(w, http.StatusOK, resp)
}

func (h Handler) refreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	var req models.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("failed to decode JSON request", "error", err)
		utils.WriteError(w, http.StatusBadRequest, "неверный формат JSON")
		return
	}

	//TODO перенести валидацию в структуру
	if req.Access == "" {
		slog.Warn("access token is missing in refresh request")
		utils.WriteError(w, http.StatusBadRequest, "access токен обязателен")
		return
	}

	if req.Refresh == "" {
		slog.Warn("refresh token is missing in refresh request")
		utils.WriteError(w, http.StatusBadRequest, "refresh токен обязателен")
		return
	}

	if req.UserID == "" {
		slog.Warn("user_id is missing in refresh request")
		utils.WriteError(w, http.StatusBadRequest, "user_id обязателен")
		return
	}

	// Валидация формата GUID
	if _, err := uuid.Parse(req.UserID); err != nil {
		slog.Warn("invalid user_id format in refresh request", "user_id", req.UserID)
		utils.WriteError(w, http.StatusBadRequest, "неверный формат user_id")
		return
	}

	// Валидация формата refresh токена (должен быть base64)
	if _, err := base64.URLEncoding.DecodeString(req.Refresh); err != nil {
		slog.Warn("invalid refresh token format (not base64)")
		utils.WriteError(w, http.StatusBadRequest, "неверный формат refresh токена")
		return
	}

	ip := utils.GetIP(r)
	userAgent := r.UserAgent()

	resp, err := h.service.RefreshTokens(r.Context(), req.UserID, req.Access, req.Refresh, userAgent, ip)
	if err != nil {
		switch {
		case errors.Is(err, apperrors.ErrTokenExpired):
			slog.Error("access token expired")
			utils.WriteError(w, http.StatusUnauthorized, "срок действия access токена истек")
		case errors.Is(err, apperrors.ErrInvalidToken):
			slog.Error("invalid token")
			utils.WriteError(w, http.StatusUnauthorized, "недействительный токен")
		case errors.Is(err, apperrors.ErrTokenRevoked):
			slog.Error("token revoked")
			utils.WriteError(w, http.StatusUnauthorized, "токен отозван")
		case errors.Is(err, apperrors.ErrTokenIsNotFound):
			slog.Error("token not found")
			utils.WriteError(w, http.StatusUnauthorized, "токен не найден")
		case errors.Is(err, apperrors.ErrTokenMismatch):
			slog.Error("token mismatch - user deauthorized")
			utils.WriteError(w, http.StatusUnauthorized, "токены не соответствуют друг другу - пользователь деавторизован")
		case errors.Is(err, apperrors.ErrUserDeauthorized):
			slog.Error("user deauthorized due to User-Agent mismatch")
			utils.WriteError(w, http.StatusUnauthorized, "пользователь деавторизован из-за несовпадения User-Agent")
		default:
			slog.Error("Внутренняя ошибка сервера", "error", err)
			utils.WriteError(w, http.StatusInternalServerError, "Внутренняя ошибка сервера")
		}

		return
	}

	utils.SendJSON(w, http.StatusOK, resp)
}

func (h Handler) meHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, "пользователь не авторизован")
		return
	}

	utils.SendJSON(w, http.StatusOK, userID)
}

func (h Handler) logoutHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, "пользователь не авторизован")
		return
	}
	if err := h.service.Logout(r.Context(), userID); err != nil {
		slog.Infof("internal error: %v", err)
		utils.WriteError(w, http.StatusInternalServerError, "ошибка деавторизации")
		return
	}

	utils.SendJSON(w, http.StatusOK, nil)
}
