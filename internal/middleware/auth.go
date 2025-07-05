package middleware

import (
	"auth-service/internal/auth"
	"auth-service/internal/service"
	"auth-service/models"
	"context"
	"encoding/json"
	"net/http"
)

func AuthMiddleware(service service.ServiceI) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" || len(header) < 8 || header[:7] != "Bearer " {
				writeError(w, http.StatusUnauthorized, "отсутствует access токен")
				return
			}
			tokenString := header[7:]
			userID, err := auth.ParseAndValidateAccessToken(tokenString)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "невалидный access токен")
				return
			}
			ok, _ := service.IsUserAuthorized(r.Context(), userID)
			if !ok {
				writeError(w, http.StatusUnauthorized, "пользователь деавторизован")
				return
			}
			ctx := context.WithValue(r.Context(), "user_id", userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(models.Error{Message: message})
}
