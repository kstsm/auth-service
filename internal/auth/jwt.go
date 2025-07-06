package auth

import (
	"auth-service/config"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"time"
)

func GenerateRefreshToken() (string, string, string, error) {
	tokenID := uuid.New().String()

	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", "", "", err
	}

	tokenBase64 := base64.URLEncoding.EncodeToString(tokenBytes)

	hash, err := bcrypt.GenerateFromPassword(tokenBytes, bcrypt.DefaultCost)
	if err != nil {
		return "", "", "", err
	}

	return tokenBase64, string(hash), tokenID, nil
}

func GenerateAccessToken(userID, userIP, userAgent, tokenPairID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":       userID,
		"user_ip":       userIP,
		"user_agent":    userAgent,
		"token_pair_id": tokenPairID,
		"exp":           time.Now().Add(15 * time.Minute).Unix(),
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

func ParseAndValidateToken(tokenString string) (jwt.MapClaims, error) {
	secretKey := config.GetConfig().JWT.Secret
	if secretKey == "" {
		return nil, fmt.Errorf("jwt secret key is not configured")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || token.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwt token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid jwt token")
}

func GetUserIDFromToken(tokenString string) (string, error) {
	claims, err := ParseAndValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", fmt.Errorf("user_id is missing in token claims")
	}
	return userID, nil
}
