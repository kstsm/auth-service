package handler

import (
	"auth-service/internal/apperrors"
	"auth-service/models"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/gookit/slog"
	"net/http"
)

func (h Handler) getTokensHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		slog.Warn("user_id отсутствует")
		writeError(w, http.StatusBadRequest, "user_id обязателен")
		return
	}

	if _, err := uuid.Parse(userID); err != nil {
		slog.Warn("user_id invalid GUID format", userID)
		writeError(w, http.StatusBadRequest, "user_id имеет неверный формат GUID")
		return
	}

	ip := getIP(r)
	userAgent := r.UserAgent()

	resp, err := h.service.GetTokens(r.Context(), userID, ip, userAgent)
	if err != nil {
		slog.Errorf("internal error: %v", err)
		writeError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
		return
	}

	sendJSON(w, http.StatusOK, resp)
}

func (h Handler) refreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	var req models.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "неверный формат JSON")
		return
	}

	if _, err := uuid.Parse(req.UserID); err != nil {
		writeError(w, http.StatusBadRequest, "неверный формат user_id")
		return
	}

	ip := getIP(r)
	userAgent := r.UserAgent()

	resp, err := h.service.RefreshTokens(r.Context(), req.UserID, req.Refresh, userAgent, ip)
	if err != nil {
		switch {
		case errors.Is(err, apperrors.ErrInvalidToken):
			slog.Error("invalid refresh token")
			writeError(w, http.StatusUnauthorized, "недействительный токен")
		default:
			slog.Error("Внутренняя ошибка сервера", "error", err)
			writeError(w, http.StatusInternalServerError, "Внутренняя ошибка сервера")

		}

		return
	}

	sendJSON(w, http.StatusOK, resp)
}

func (h Handler) meHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		writeError(w, http.StatusUnauthorized, "пользователь не авторизован")
		return
	}

	sendJSON(w, http.StatusOK, userID)
}

func (h Handler) logoutHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		writeError(w, http.StatusUnauthorized, "пользователь не авторизован")
		return
	}
	if err := h.service.Logout(r.Context(), userID); err != nil {
		slog.Infof("internal error: %v", err)
		writeError(w, http.StatusInternalServerError, "ошибка деавторизации")
		return
	}

	sendJSON(w, http.StatusOK, nil)
}
