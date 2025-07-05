package apperrors

import "errors"

var (
	ErrTokenIsNotFound  = errors.New("errTokenIsNotFound")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrInvalidInput     = errors.New("invalid input")
	ErrTokenRevoked     = errors.New("token revoked")
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenMismatch    = errors.New("token mismatch")
	ErrTokenExpired     = errors.New("token expired")
	ErrUserDeauthorized = errors.New("user deauthorized")
)
