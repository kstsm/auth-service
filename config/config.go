package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	Server   Server
	Postgres Postgres
	JWT      JWT
	Webhook  Webhook
}

type Server struct {
	Host string
	Port int
}

type Postgres struct {
	Username string
	Password string
	Host     string
	Port     string
	DBName   string
	SSLMode  string
}

type JWT struct {
	Secret string
}

type Webhook struct {
	URL string
}

func GetConfig() Config {
	viper.SetConfigFile(".env")

	err := viper.ReadInConfig()
	if err != nil {
		panic("Failed to read .env file: " + err.Error())
	}

	return Config{
		Server: Server{
			Host: viper.GetString("SRV_HOST"),
			Port: viper.GetInt("SRV_PORT"),
		},
		Postgres: Postgres{
			Username: viper.GetString("POSTGRES_USER"),
			Password: viper.GetString("POSTGRES_PASSWORD"),
			Host:     viper.GetString("POSTGRES_HOST"),
			Port:     viper.GetString("POSTGRES_PORT"),
			DBName:   viper.GetString("POSTGRES_DB"),
		},
		JWT: JWT{
			Secret: viper.GetString("SECRET_KEY"),
		},
		Webhook: Webhook{
			URL: viper.GetString("WEBHOOK_URL"),
		},
	}
}
