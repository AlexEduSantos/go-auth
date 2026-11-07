DROP INDEX IF EXISTS idx_app_logs_created_at;
DROP INDEX IF EXISTS idx_app_logs_payload;
DROP TABLE IF EXISTS app_logs;

ALTER TABLE users
    DROP COLUMN IF EXISTS reset_password_expires,
    DROP COLUMN IF EXISTS reset_password_token;
