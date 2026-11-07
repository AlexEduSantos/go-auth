-- Habilita extensão para UUIDs aleatórios
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Cria o Enum para as Roles de Usuário (idempotente)
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('ADMIN', 'PUBLISHER', 'MANAGER', 'USER');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Tabela de Usuários
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role user_role DEFAULT 'USER' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Sessões / Refresh Tokens
CREATE TABLE IF NOT EXISTS session (
    sid VARCHAR PRIMARY KEY,
    sess JSONB NOT NULL,
    expire TIMESTAMP(6) NOT NULL
);

CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON session (expire);
