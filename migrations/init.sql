DROP TABLE refresh_tokens


CREATE TABLE refresh_tokens
(
    id            SERIAL PRIMARY KEY,
    user_id       UUID        NOT NULL,
    token_hash    VARCHAR(60) NOT NULL,
    token_pair_id UUID,
    user_agent    TEXT        NOT NULL,
    ip            INET        NOT NULL,
    revoked       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_token_pair_id ON refresh_tokens (token_pair_id);


CREATE TABLE refresh_tokens
(
    id            SERIAL PRIMARY KEY,
    user_id       UUID        NOT NULL,
    token_hash    VARCHAR(60) NOT NULL,
    token_pair_id UUID        NOT NULL,
    user_agent    TEXT        NOT NULL,
    ip            TEXT        NOT NULL,
    revoked       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMP   NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_token_pair_id ON refresh_tokens (token_pair_id);