package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var Log *slog.Logger

// DBLogWriter implementa io.Writer para gravar logs do slog no PostgreSQL de forma assíncrona
type DBLogWriter struct {
	db *pgxpool.Pool
}

func (w *DBLogWriter) Write(p []byte) (n int, err error) {
	if w.db == nil {
		return len(p), nil
	}

	// Faz uma cópia segura do slice de bytes para ser processada em background
	logCopy := append([]byte(nil), p...)

	go func(data []byte) {
		var parsed map[string]interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			return
		}

		level, _ := parsed["level"].(string)
		msg, _ := parsed["msg"].(string)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, _ = w.db.Exec(ctx,
			`INSERT INTO app_logs (level, message, payload) VALUES ($1, $2, $3)`,
			level, msg, data,
		)
	}(logCopy)

	return len(p), nil
}

// InitLogger inicializa o logger estruturado em formato JSON (Terminal + PostgreSQL)
func InitLogger(db *pgxpool.Pool) {
	var writer io.Writer = os.Stdout

	if db != nil {
		dbWriter := &DBLogWriter{db: db}
		writer = io.MultiWriter(os.Stdout, dbWriter)
	}

	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{
		Level: slog.LevelInfo, // Nível mínimo de log (Info, Warn, Error)
	})
	Log = slog.New(handler)
	slog.SetDefault(Log)
}

// StartLogCleanup executa uma rotina periódica para apagar logs antigos (ex: mais de 30 dias)
func StartLogCleanup(ctx context.Context, db *pgxpool.Pool, interval time.Duration, retentionDays int) {
	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()

		query := fmt.Sprintf(`DELETE FROM app_logs WHERE created_at < NOW() - INTERVAL '%d days'`, retentionDays)

		for {
			select {
			case <-ticker.C:
				if _, err := db.Exec(ctx, query); err != nil {
					log.Printf("[Worker] Erro ao limpar logs antigos: %v\n", err)
				} else {
					log.Println("[Worker] Logs antigos limpos com sucesso.")
				}
			case <-ctx.Done():
				log.Println("[Worker] Parando a rotina de limpeza de logs.")
				return
			}
		}
	}()
}

