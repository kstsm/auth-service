package utils

import (
	"auth-service/config"
	"auth-service/models"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gookit/slog"
	"net"
	"net/http"
	"strings"
)

func SendJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if data == nil {
		return
	}

	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Ошибка при отправке ответа", http.StatusInternalServerError)
	}
}

func WriteError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(models.Error{Message: message})
}

func GetIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

func NotifyNewIP(userID, oldIP, newIP, userAgent string) {
	webhookURL := config.GetConfig().Webhook.URL
	if webhookURL == "" {
		return
	}
	payload := map[string]interface{}{
		"user_id":    userID,
		"old_ip":     oldIP,
		"new_ip":     newIP,
		"user_agent": userAgent,
	}
	err := SendWebhook(webhookURL, payload)
	if err != nil {
		slog.Error("failed to send webhook", "err", err)
	}
}

func SendWebhook(url string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
