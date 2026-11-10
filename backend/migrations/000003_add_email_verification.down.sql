DROP INDEX IF EXISTS idx_verification_tokens_expires_at;
DROP INDEX IF EXISTS idx_verification_tokens_user_id;
DROP TABLE IF EXISTS verification_tokens;

ALTER TABLE users
    DROP COLUMN IF EXISTS is_verified;
