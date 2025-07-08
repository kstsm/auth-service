package middleware

import (
	"auth-service/internal/auth"
	"auth-service/internal/utils"
	"context"
	"net/http"
	"strings"
)

func AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			authHeader := r.Header.Get("Authorization")
			tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			if tokenString == "" {
				utils.WriteError(w, http.StatusUnauthorized, "отсутствует или пустой access токен")
				return
			}

			userID, err := auth.GetUserIDFromToken(tokenString)
			if err != nil {
				utils.WriteError(w, http.StatusUnauthorized, "невалидный access токен")
				return
			}

			ctx := context.WithValue(r.Context(), "user_id", userID)
			ctx = context.WithValue(ctx, "access_token", tokenString)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
