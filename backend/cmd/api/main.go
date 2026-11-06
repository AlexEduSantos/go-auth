package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/AlexEduSantos/go-auth/internal/handlers"
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
	fmt.Println("Conexão com o PostgreSQL estabelecida com sucesso!")

	// Inicializa dependências (Clean Architecture básica)
	userRepo := repository.NewUserRepository(dbPool)
	sessionRepo := repository.NewSessionRepository(dbPool)
	authHandler := handlers.NewAuthHandler(userRepo, sessionRepo)
	repository.StartSessionCleanup(ctx, sessionRepo, 1*time.Hour)

	limiter := middleware.NewIPRateLimiter(rate.Every(5*time.Second), 5)

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/register", authHandler.Register)
	mux.HandleFunc("POST /api/login", limiter.Middleware(authHandler.Login))
	mux.HandleFunc("POST /api/forgot-password", limiter.Middleware(authHandler.ForgotPassword))
	mux.HandleFunc("POST /api/reset-password", limiter.Middleware(authHandler.ResetPassword))

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("API rodando perfeitamente!"))
	})

	fmt.Println("Servidor rodando na porta 8080...")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("Erro ao iniciar servidor: %v", err)
	}
}
