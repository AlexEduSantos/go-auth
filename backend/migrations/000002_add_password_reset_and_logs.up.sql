-- Colunas para recuperação de senha na tabela users
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS reset_password_token VARCHAR(255),
    ADD COLUMN IF NOT EXISTS reset_password_expires TIMESTAMP WITH TIME ZONE;

-- Tabela de Logs Estruturados (slog)
CREATE TABLE IF NOT EXISTS app_logs (
    id BIGSERIAL PRIMARY KEY,
    level VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_app_logs_payload ON app_logs USING GIN (payload);
CREATE INDEX IF NOT EXISTS idx_app_logs_created_at ON app_logs (created_at);
