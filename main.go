package main

import (
	"auth-service/cmd"
	_ "auth-service/docs"
	"net/http"
)

// @title Auth Service API
// @version 1.0
// @description API для аутентификации и управления токенами
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @BasePath /

func main() {
	cmd.Run()
	http.Handle("/swagger/", http.StripPrefix("/swagger/", http.FileServer(http.Dir("./docs"))))
}
