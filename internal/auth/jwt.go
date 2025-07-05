package auth

import (
	"auth-service/config"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"time"
)

func GenerateRefreshToken() (string, string, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		return "", "", fmt.Errorf("generate random bytes: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword(b, bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("bcrypt hash: %w", err)
	}

	token := base64.URLEncoding.EncodeToString(b)

	return string(hash), token, nil
}

func GenerateAccessToken(userID, userIP string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"user_ip": userIP,
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	secretKey := config.GetConfig().JWT.Secret
	if secretKey == "" {
		return "", fmt.Errorf("jwt secret key is not configured")
	}

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("sign jwt token: %w", err)
	}

	return tokenString, nil
}

func ParseAndValidateAccessToken(tokenString string) (string, error) {
	secretKey := config.GetConfig().JWT.Secret
	if secretKey == "" {
		return "", fmt.Errorf("jwt secret key is not configured")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || token.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse jwt token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["user_id"].(string)
		if !ok {
			return "", fmt.Errorf("user_id is missing in token claims")
		}
		return userID, nil
	}

	return "", fmt.Errorf("invalid jwt token")
}
