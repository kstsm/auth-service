package apperrors

import "errors"

var (
	ErrTokenExpired     = errors.New("token expired")
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenRevoked     = errors.New("token revoked")
	ErrTokenIsNotFound  = errors.New("token not found")
	ErrUserDeauthorized = errors.New("user deauthorized")
	ErrAlreadyLoggedOut = errors.New("user already logged out")
)
