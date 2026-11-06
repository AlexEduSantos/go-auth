package repository

import (
	"context"

	"github.com/AlexEduSantos/go-auth/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"

	"time"
)

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

// Create insere um novo usuário e retorna os dados gerados pelo banco (ID, datas)
func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (username, name, email, password, role)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		user.Username,
		user.Name,
		user.Email,
		user.Password,
		user.Role,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	return err
}

func (r *UserRepository) FindByIdentifier(ctx context.Context, identifier string) (*models.User, error) {
	query := `
		SELECT id, username, name, email, password, role, created_at, updated_at
		FROM users
		WHERE email = $1 OR username = $1
	`
	user := &models.User{}
	err := r.db.QueryRow(ctx, query, identifier).Scan(
		&user.ID,
		&user.Username,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// Salva o token de recuperação e a expiração para um determinado email
func (r *UserRepository) SavePasswordResetToken(ctx context.Context, email, token string, expiresAt time.Time) error {
	query := `
		UPDATE users 
		SET reset_password_token = $1, reset_password_expires = $2, updated_at = CURRENT_TIMESTAMP
		WHERE email = $3
	`
	_, err := r.db.Exec(ctx, query, token, expiresAt, email)
	return err
}

// Busca um usuário por um token de recuperação válido e não expirado
func (r *UserRepository) FindByResetToken(ctx context.Context, token string) (*models.User, error) {
	query := `
		SELECT id, username, name, email, password, role, created_at, updated_at
		FROM users
		WHERE reset_password_token = $1 AND reset_password_expires > CURRENT_TIMESTAMP
	`
	user := &models.User{}
	err := r.db.QueryRow(ctx, query, token).Scan(
		&user.ID,
		&user.Username,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// Atualiza a senha do usuário e limpa os campos de token de recuperação
func (r *UserRepository) UpdatePasswordAndClearToken(ctx context.Context, userID string, hashedNewPassword string) error {
	query := `
		UPDATE users 
		SET password = $1, reset_password_token = NULL, reset_password_expires = NULL, updated_at = CURRENT_TIMESTAMP
		WHERE id = $2
	`
	_, err := r.db.Exec(ctx, query, hashedNewPassword, userID)
	return err
}
