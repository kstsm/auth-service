package middleware

import (
	"auth-service/internal/auth"
	"auth-service/internal/service"
	"auth-service/internal/utils"
	"context"
	"net/http"
)

func AuthMiddleware(service service.ServiceI) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" || len(header) < 8 || header[:7] != "Bearer " {
				utils.WriteError(w, http.StatusUnauthorized, "отсутствует access токен")
				return
			}
			tokenString := header[7:]
			userID, err := auth.GetUserIDFromToken(tokenString)
			if err != nil {
				utils.WriteError(w, http.StatusUnauthorized, "невалидный access токен")
				return
			}
			ok, _ := service.IsUserAuthorized(r.Context(), userID)
			if !ok {
				utils.WriteError(w, http.StatusUnauthorized, "пользователь деавторизован")
				return
			}
			ctx := context.WithValue(r.Context(), "user_id", userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
