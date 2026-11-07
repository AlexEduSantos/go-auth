package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/AlexEduSantos/go-auth/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

// Tipo próprio para chaves de contexto (evita colisões entre pacotes)
type contextKey string

const (
	UserIDKey   contextKey = "user_id"
	UserRoleKey contextKey = "user_role"
	SIDKey      contextKey = "sid"
)

var jwtSecret = []byte("sua_chave_secreta_super_segura_aqui")

// 1. AuthMiddleware: lê o cookie auth_token, valida o JWT e salva os dados no Context
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Não autorizado: Token ausente", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Erro ao ler token", http.StatusBadRequest)
			return
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("método de assinatura inesperado: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Não autorizado: Token inválido ou expirado", http.StatusUnauthorized)
			return
		}

		// Extrai user_id, role e sid das claims
		userID, _ := claims["sub"].(string)
		roleStr, _ := claims["role"].(string)
		sid, _ := claims["sid"].(string)

		// Guarda os dados tipados no Contexto da requisição
		ctx := context.WithValue(r.Context(), UserIDKey, userID)
		ctx = context.WithValue(ctx, UserRoleKey, models.UserRole(roleStr))
		ctx = context.WithValue(ctx, SIDKey, sid)

		next(w, r.WithContext(ctx))
	}
}

// 2. RequireRole: checa se o usuário autenticado possui uma das roles permitidas (ADMIN, USER, etc.)
func RequireRole(next http.HandlerFunc, allowedRoles ...models.UserRole) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userRole, ok := r.Context().Value(UserRoleKey).(models.UserRole)
		if !ok || userRole == "" {
			http.Error(w, "Não autorizado: Role não identificada", http.StatusUnauthorized)
			return
		}

		for _, role := range allowedRoles {
			if userRole == role {
				next(w, r)
				return
			}
		}

		http.Error(w, "Acesso negado: você não tem permissão para acessar este recurso", http.StatusForbidden)
	}
}

