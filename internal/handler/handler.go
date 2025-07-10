package handler

import (
	"auth-service/internal/middleware"
	"auth-service/internal/service"
	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger"
	"net/http"
)

type HandlerI interface {
	NewRouter() http.Handler
}

type Handler struct {
	service service.ServiceI
}

func NewHandler(service service.ServiceI) HandlerI {
	return &Handler{
		service: service,
	}
}

func (h Handler) NewRouter() http.Handler {
	r := chi.NewRouter()

	r.Get("/swagger/*", h.swaggerHandler())

	r.Post("/token", h.generateTokensHandler)
	r.Post("/token/refresh", h.refreshTokensHandler)

	r.Route("/", func(r chi.Router) {
		r.Use(middleware.AuthMiddleware())

		r.Get("/me", h.meHandler)
		r.Post("/logout", h.logoutHandler)
	})

	return r
}

func (h Handler) swaggerHandler() http.HandlerFunc {
	return httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	)
}
