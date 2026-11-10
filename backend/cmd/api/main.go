package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/AlexEduSantos/go-auth/internal/database"
	"github.com/AlexEduSantos/go-auth/internal/docs"
	"github.com/AlexEduSantos/go-auth/internal/handlers"
	"github.com/AlexEduSantos/go-auth/internal/logger"
	"github.com/AlexEduSantos/go-auth/internal/middleware"
	"github.com/AlexEduSantos/go-auth/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	"time"
)

func main() {
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, dbPassword, dbHost, dbPort, dbName,
	)

	ctx := context.Background()
	dbPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("Erro ao criar pool de conexões: %v\n", err)
	}
	defer dbPool.Close()

	if err = dbPool.Ping(ctx); err != nil {
		log.Fatalf("Erro ao conectar com o banco de dados: %v\n", err)
	}

	// Inicializa o logger estruturado (Terminal + PostgreSQL) e a rotina de limpeza (retenção de 30 dias)
	logger.InitLogger(dbPool)

	// Executa migrações versionadas embutidas no binário automaticamente ao subir a aplicação
	if err := database.RunMigrations(ctx, dbPool); err != nil {
		logger.Log.Error("Falha ao executar migrações do banco", "error", err.Error())
		log.Fatalf("Erro nas migrações: %v\n", err)
	}

	logger.StartLogCleanup(ctx, dbPool, 24*time.Hour, 30)
	logger.Log.Info("Conexão com o PostgreSQL estabelecida com sucesso!")

	// Inicializa dependências (Clean Architecture básica)
	userRepo := repository.NewUserRepository(dbPool)
	sessionRepo := repository.NewSessionRepository(dbPool)
	authHandler := handlers.NewAuthHandler(userRepo, sessionRepo)
	repository.StartSessionCleanup(ctx, sessionRepo, 1*time.Hour)

	limiter := middleware.NewIPRateLimiter(rate.Every(5*time.Second), 5)

	mux := http.NewServeMux()

	// Rotas de Autenticação e Segurança
	mux.HandleFunc("GET /api/csrf-token", limiter.Middleware(middleware.CSRFTokenHandler))
	mux.HandleFunc("POST /api/register", limiter.Middleware(authHandler.Register))
	mux.HandleFunc("GET /api/verify", limiter.Middleware(authHandler.VerifyEmail))
	mux.HandleFunc("POST /api/verify", limiter.Middleware(authHandler.VerifyEmail))
	mux.HandleFunc("POST /api/login", limiter.Middleware(authHandler.Login))
	mux.HandleFunc("POST /api/auth/magic-link", limiter.Middleware(authHandler.RequestMagicLink))
	mux.HandleFunc("GET /api/auth/verify-otp", limiter.Middleware(authHandler.VerifyOTP))
	mux.HandleFunc("POST /api/auth/verify-otp", limiter.Middleware(authHandler.VerifyOTP))
	mux.HandleFunc("POST /api/refresh", limiter.Middleware(authHandler.Refresh))
	mux.HandleFunc("POST /api/logout", limiter.Middleware(middleware.AuthMiddleware(authHandler.Logout)))
	mux.HandleFunc("POST /api/forgot-password", limiter.Middleware(authHandler.ForgotPassword))
	mux.HandleFunc("POST /api/reset-password", limiter.Middleware(authHandler.ResetPassword))

	// Documentação Interativa Swagger (OpenAPI 3.0)
	mux.HandleFunc("GET /swagger", docs.SwaggerUIHandler)
	mux.HandleFunc("GET /openapi.json", docs.OpenAPIHandler)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("API rodando perfeitamente!"))
	})

	// Envolve todas as rotas com Security Headers, Proteção CSRF (Double Submit Cookie) e Request Logger
	securedMux := middleware.SecurityHeaders(
		middleware.CSRFMiddleware(
			middleware.RequestLogger(mux),
		),
	)

	logger.Log.Info("Servidor rodando na porta 8080...")
	if err := http.ListenAndServe(":8080", securedMux); err != nil {
		log.Fatalf("Erro ao iniciar servidor: %v", err)
	}
}
