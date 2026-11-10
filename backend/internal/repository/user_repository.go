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

// Create insere um novo usuário (com is_verified = false por padrão) e retorna os dados gerados pelo banco
func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (username, name, email, password, role, is_verified)
		VALUES ($1, $2, $3, $4, $5, FALSE)
		RETURNING id, is_verified, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		user.Username,
		user.Name,
		user.Email,
		user.Password,
		user.Role,
	).Scan(&user.ID, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt)

	return err
}

func (r *UserRepository) FindByIdentifier(ctx context.Context, identifier string) (*models.User, error) {
	query := `
		SELECT id, username, name, email, password, role, is_verified, created_at, updated_at
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
		&user.IsVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// SaveVerificationToken armazena o token de confirmação de e-mail na tabela verification_tokens
func (r *UserRepository) SaveVerificationToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	query := `
		INSERT INTO verification_tokens (token, user_id, expires_at)
		VALUES ($1, $2, $3)
	`
	_, err := r.db.Exec(ctx, query, token, userID, expiresAt)
	return err
}

// VerifyUserByToken valida o token na tabela verification_tokens, ativa is_verified = true no utilizador
// e apaga o token utilizado dentro de uma única transação atómica.
func (r *UserRepository) VerifyUserByToken(ctx context.Context, token string) (string, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	findQuery := `
		SELECT user_id
		FROM verification_tokens
		WHERE token = $1 AND expires_at > CURRENT_TIMESTAMP
	`
	if err := tx.QueryRow(ctx, findQuery, token).Scan(&userID); err != nil {
		return "", err
	}

	updateQuery := `
		UPDATE users
		SET is_verified = TRUE, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`
	if _, err := tx.Exec(ctx, updateQuery, userID); err != nil {
		return "", err
	}

	deleteQuery := `DELETE FROM verification_tokens WHERE user_id = $1`
	if _, err := tx.Exec(ctx, deleteQuery, userID); err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}

	return userID, nil
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
		SELECT id, username, name, email, password, role, is_verified, created_at, updated_at
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
		&user.IsVerified,
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

// SavePasswordlessToken remove códigos anteriores do utilizador e grava um novo OTP de 6 dígitos + Magic Link
func (r *UserRepository) SavePasswordlessToken(ctx context.Context, userID, otpCode, magicToken string, expiresAt time.Time) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM passwordless_tokens WHERE user_id = $1`, userID); err != nil {
		return err
	}

	insertQuery := `
		INSERT INTO passwordless_tokens (user_id, otp_code, magic_token, expires_at)
		VALUES ($1, $2, $3, $4)
	`
	if _, err := tx.Exec(ctx, insertQuery, userID, otpCode, magicToken, expiresAt); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ConsumePasswordlessToken valida um código OTP de 6 dígitos (associado ao email/username) ou um Magic Token,
// apaga imediatamente o registo para impedir reutilização, garante is_verified = true e retorna o utilizador.
func (r *UserRepository) ConsumePasswordlessToken(ctx context.Context, identifier, codeOrToken string) (*models.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	user := &models.User{}
	var query string
	var args []interface{}

	if identifier != "" {
		query = `
			SELECT u.id, u.username, u.name, u.email, u.password, u.role, u.is_verified, u.created_at, u.updated_at
			FROM passwordless_tokens pt
			JOIN users u ON u.id = pt.user_id
			WHERE (u.email = $1 OR u.username = $1)
			  AND (pt.otp_code = $2 OR pt.magic_token = $2)
			  AND pt.expires_at > CURRENT_TIMESTAMP
		`
		args = []interface{}{identifier, codeOrToken}
	} else {
		query = `
			SELECT u.id, u.username, u.name, u.email, u.password, u.role, u.is_verified, u.created_at, u.updated_at
			FROM passwordless_tokens pt
			JOIN users u ON u.id = pt.user_id
			WHERE pt.magic_token = $1
			  AND pt.expires_at > CURRENT_TIMESTAMP
		`
		args = []interface{}{codeOrToken}
	}

	err = tx.QueryRow(ctx, query, args...).Scan(
		&user.ID,
		&user.Username,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.IsVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Invalida imediatamente o código usado (One-Time Password)
	if _, err := tx.Exec(ctx, `DELETE FROM passwordless_tokens WHERE user_id = $1`, user.ID); err != nil {
		return nil, err
	}

	// Se o utilizador ainda não estava verificado, a posse do e-mail via OTP/Magic Link confirma a conta
	if !user.IsVerified {
		if _, err := tx.Exec(ctx, `UPDATE users SET is_verified = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1`, user.ID); err != nil {
			return nil, err
		}
		user.IsVerified = true
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return user, nil
}

