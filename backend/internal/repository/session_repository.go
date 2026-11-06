package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionRepository struct {
	db *pgxpool.Pool
}

func NewSessionRepository(db *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{db: db}
}

// Criar ou Atualizar uma sessão (Upsert)
func (r *SessionRepository) Save(ctx context.Context, sid string, sessData []byte, expire time.Time) error {
	query := `
		INSERT INTO session (sid, sess, expire)
		VALUES ($1, $2, $3)
		ON CONFLICT (sid) DO UPDATE 
		SET sess = EXCLUDED.sess, expire = EXCLUDED.expire
	`
	_, err := r.db.Exec(ctx, query, sid, sessData, expire)
	return err
}

// Buscar uma sessão ativa pelo ID (sid)
func (r *SessionRepository) Find(ctx context.Context, sid string) ([]byte, error) {
	query := `
		SELECT sess FROM session
		WHERE sid = $1 AND expire > CURRENT_TIMESTAMP
	`
	var sessData []byte
	err := r.db.QueryRow(ctx, query, sid).Scan(&sessData)
	if err != nil {
		return nil, err
	}
	return sessData, nil
}

// Deletar/Destruir uma sessão (Logout)
func (r *SessionRepository) Delete(ctx context.Context, sid string) error {
	query := `DELETE FROM session WHERE sid = $1`
	_, err := r.db.Exec(ctx, query, sid)
	return err
}

// Limpar sessões expiradas (Pode ser chamado periodicamente)
func (r *SessionRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM session WHERE expire <= CURRENT_TIMESTAMP`
	_, err := r.db.Exec(ctx, query)
	return err
}
