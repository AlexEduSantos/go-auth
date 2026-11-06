package repository

import (
	"context"
	"log"
	"time"
)

// StartSessionCleanup executa uma rotina periódica para apagar sessões expiradas
func StartSessionCleanup(ctx context.Context, repo *SessionRepository, interval time.Duration) {
	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Executa a query de limpeza que já definimos no repositório
				err := repo.DeleteExpired(ctx)
				if err != nil {
					log.Printf("[Worker] Erro ao limpar sessões expiradas: %v\n", err)
				} else {
					log.Println("[Worker] Sessões expiradas limpas com sucesso.")
				}
			case <-ctx.Done():
				log.Println("[Worker] Parando a rotina de limpeza de sessões.")
				return
			}
		}
	}()
}
