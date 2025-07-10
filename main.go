package main

import (
	"auth-service/cmd"
	_ "auth-service/docs"
)

// @title Auth Service API
// @version 1.0
// @description API для аутентификации и управления токенами
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @BasePath /
// @host localhost:8080
// @schemes http
// @contact.name API Support
// @contact.email support@example.com

func main() {
	cmd.Run()
}
