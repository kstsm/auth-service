package handler

import (
	"auth-service/internal/middleware"
	"auth-service/internal/service"
	"github.com/go-chi/chi/v5"
	"net/http"
)

type HandlerI interface {
	NewRouter() http.Handler
	generateTokensHandler(w http.ResponseWriter, r *http.Request)
	refreshTokensHandler(w http.ResponseWriter, r *http.Request)
	meHandler(w http.ResponseWriter, r *http.Request)
	logoutHandler(w http.ResponseWriter, r *http.Request)
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

	r.Post("/token", h.generateTokensHandler)
	r.Post("/token/refresh", h.refreshTokensHandler)

	r.Route("/", func(r chi.Router) {
		r.Use(middleware.AuthMiddleware())

		r.Get("/me", h.meHandler)
		r.Post("/logout", h.logoutHandler)
	})

	return r
}
