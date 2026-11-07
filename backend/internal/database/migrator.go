package database

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"

	"github.com/AlexEduSantos/go-auth/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RunMigrations executa os arquivos *.up.sql embutidos no binário (embed.FS) em ordem sequencial,
// mantendo o controle na tabela schema_migrations (padrão compatível com golang-migrate).
func RunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);
	`
	if _, err := db.Exec(ctx, createTableQuery); err != nil {
		return fmt.Errorf("erro ao criar tabela schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("erro ao ler migrações embutidas: %w", err)
	}

	var upFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".up.sql") {
			upFiles = append(upFiles, entry.Name())
		}
	}
	sort.Strings(upFiles)

	for _, fileName := range upFiles {
		version := strings.TrimSuffix(fileName, ".up.sql")

		var exists bool
		err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("erro ao verificar migração %s: %w", version, err)
		}
		if exists {
			continue
		}

		sqlBytes, err := fs.ReadFile(migrations.FS, fileName)
		if err != nil {
			return fmt.Errorf("erro ao ler arquivo %s: %w", fileName, err)
		}

		tx, err := db.Begin(ctx)
		if err != nil {
			return fmt.Errorf("erro ao iniciar transação na migração %s: %w", version, err)
		}

		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("erro ao aplicar migração %s: %w", version, err)
		}

		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("erro ao registrar migração %s: %w", version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("erro ao comitar migração %s: %w", version, err)
		}

		slog.Info("Migração aplicada com sucesso", slog.String("version", version))
	}

	return nil
}
