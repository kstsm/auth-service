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

// generateTokensHandler godoc
// @Summary Генерация access и refresh токенов
// @Description Генерирует пару токенов для пользователя
// @Tags auth
// @Accept json
// @Produce json
// @Param user_id query string true "ID пользователя"
// @Success 200 {object} models.TokensResponse "Успешный ответ"
// @Failure 400 {object} models.Error "Некорректный запрос"
// @Failure 500 {object} models.Error "Внутренняя ошибка сервера"
// @Router /token [post]
// @Example request {"user_id": "b3b3b3b3-b3b3-b3b3-b3b3-b3b3b3b3b3b3"}
// @Example success {"access": "eyJhbGciOiJIUzI1NiIsInR5cCI6...", "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6..."}
// @Example error {"message": "user_id обязателен"}
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

// refreshTokensHandler godoc
// @Summary Обновление access и refresh токенов
// @Description Обновляет пару токенов по refresh токену
// @Tags auth
// @Accept json
// @Produce json
// @Param data body models.RefreshRequest true "Данные для обновления токенов"
// @Success 200 {object} models.TokensResponse "Успешный ответ"
// @Failure 400 {object} models.Error "Некорректный запрос"
// @Failure 401 {object} models.Error "Ошибка авторизации"
// @Failure 500 {object} models.Error "Внутренняя ошибка сервера"
// @Router /token/refresh [post]
// @Example request {"user_id": "b3b3b3b3-b3b3-b3b3-b3b3-b3b3b3b3b3b3", "access": "...", "refresh": "..."}
// @Example success {"access": "eyJhbGciOiJIUzI1NiIsInR5cCI6...", "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6..."}
// @Example error {"message": "недействительный токен"}
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

// meHandler godoc
// @Summary Получить информацию о пользователе
// @Description Возвращает user_id авторизованного пользователя
// @Tags user
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string "Успешный ответ"
// @Failure 401 {object} models.Error "Ошибка авторизации"
// @Failure 500 {object} models.Error "Внутренняя ошибка сервера"
// @Router /me [get]
// @Security BearerAuth
// @Example success {"user_id": "b3b3b3b3-b3b3-b3b3-b3b3-b3b3b3b3b3b3"}
// @Example error {"message": "пользователь не авторизован"}
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

// logoutHandler godoc
// @Summary Деавторизация пользователя
// @Description Деавторизует пользователя и отзывает токены
// @Tags user
// @Accept json
// @Produce json
// @Success 200 {object} nil "Успешный ответ"
// @Failure 401 {object} models.Error "Ошибка авторизации"
// @Failure 500 {object} models.Error "Внутренняя ошибка сервера"
// @Router /logout [post]
// @Security BearerAuth
// @Example error {"message": "пользователь уже деавторизован"}
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
