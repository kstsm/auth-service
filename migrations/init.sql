CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash TEXT NOT NULL,
    token_pair_id VARCHAR(36),
    user_agent TEXT NOT NULL,
    ip TEXT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

