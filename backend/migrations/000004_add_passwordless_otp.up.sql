-- Tabela para autenticação Passwordless (OTP de 6 dígitos e Magic Link) com proteção contra força bruta
CREATE TABLE IF NOT EXISTS passwordless_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp_code VARCHAR(6) NOT NULL,
    magic_token VARCHAR(255) UNIQUE NOT NULL,
    attempts INT DEFAULT 0 NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE passwordless_tokens
    ADD COLUMN IF NOT EXISTS attempts INT DEFAULT 0 NOT NULL;

CREATE INDEX IF NOT EXISTS idx_passwordless_tokens_user_id ON passwordless_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_passwordless_tokens_magic_token ON passwordless_tokens (magic_token);
CREATE INDEX IF NOT EXISTS idx_passwordless_tokens_expires_at ON passwordless_tokens (expires_at);
