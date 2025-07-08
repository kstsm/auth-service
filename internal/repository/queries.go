package repository

const (
	queryFindRefreshTokenByPairID = `
		SELECT id, user_id, token_hash, token_pair_id, user_agent, ip, revoked, created_at
		FROM refresh_tokens
		WHERE user_id = $1
		AND token_pair_id = $2`

	querySaveRefreshToken = `
		INSERT INTO refresh_tokens (user_id, token_hash, token_pair_id, user_agent, ip) 
		VALUES ($1, $2, $3, $4, $5)`
)
