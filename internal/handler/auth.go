package handler

import (
	"auth-service/internal/apperrors"
	"auth-service/internal/utils"
	"auth-service/models"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"net/http"
	"strings"
)

func (h Handler) generateTokensHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		utils.WriteError(w, http.StatusBadRequest, "user_id обязателен")
		return
	}

	if _, err := uuid.Parse(userID); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "неверный формат user_id")
		return
	}

	ip := utils.GetIP(r)
	userAgent := r.UserAgent()

	resp, err := h.service.GenerateTokens(r.Context(), userID, ip, userAgent)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "ошибка генерации токенов")
		return
	}

	utils.SendJSON(w, http.StatusOK, resp)
}

func (h Handler) refreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	var req models.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "неверный формат JSON")
		return
	}

	if req.UserID == "" || req.Access == "" || req.Refresh == "" {
		utils.WriteError(w, http.StatusBadRequest, "все поля обязательны")
		return
	}

	if _, err := uuid.Parse(req.UserID); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "неверный формат user_id")
		return
	}

	ip := utils.GetIP(r)
	userAgent := r.UserAgent()

	resp, err := h.service.RefreshTokens(r.Context(), req.UserID, req.Access, req.Refresh, userAgent, ip)
	if err != nil {
		switch {
		case errors.Is(err, apperrors.ErrTokenExpired):
			utils.WriteError(w, http.StatusUnauthorized, "срок действия токена истек")
		case errors.Is(err, apperrors.ErrInvalidToken):
			utils.WriteError(w, http.StatusUnauthorized, "недействительный токен")
		case errors.Is(err, apperrors.ErrTokenRevoked):
			utils.WriteError(w, http.StatusUnauthorized, "токен отозван")
		case errors.Is(err, apperrors.ErrTokenIsNotFound):
			utils.WriteError(w, http.StatusUnauthorized, "токен не найден")
		case errors.Is(err, apperrors.ErrUserDeauthorized):
			utils.WriteError(w, http.StatusUnauthorized, "пользователь деавторизован")
		case errors.Is(err, apperrors.ErrAlreadyLoggedOut):
			utils.WriteError(w, http.StatusUnauthorized, "пользователь уже деавторизован")
		default:
			utils.WriteError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
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

	accessToken, ok := r.Context().Value("access_token").(string)
	if !ok || accessToken == "" {
		utils.WriteError(w, http.StatusUnauthorized, "access токен не найден")
		return
	}

	claims, err := h.service.ParseAccessTokenClaims(accessToken)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "невалидный access токен")
		return
	}

	pairID, ok := claims["token_pair_id"].(string)
	if !ok || pairID == "" {
		utils.WriteError(w, http.StatusUnauthorized, "token_pair_id отсутствует в токене")
		return
	}

	revoked, err := h.service.IsRefreshTokenRevoked(r.Context(), userID, pairID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "ошибка проверки статуса токена")
		return
	}
	if revoked {
		utils.WriteError(w, http.StatusUnauthorized, "пользователь деавторизован")
		return
	}

	utils.SendJSON(w, http.StatusOK, map[string]string{"user_id": userID})
}

func (h Handler) logoutHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("user_id").(string)

	accessToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	if err := h.service.Logout(r.Context(), userID, accessToken); err != nil {
		switch {
		case errors.Is(err, apperrors.ErrAlreadyLoggedOut):
			utils.WriteError(w, http.StatusUnauthorized, "пользователь уже деавторизован")
		case errors.Is(err, apperrors.ErrInvalidToken):
			utils.WriteError(w, http.StatusUnauthorized, "недействительный токен")
		default:
			utils.WriteError(w, http.StatusInternalServerError, "ошибка деавторизации")
		}
		return
	}

	utils.SendJSON(w, http.StatusOK, nil)
}
