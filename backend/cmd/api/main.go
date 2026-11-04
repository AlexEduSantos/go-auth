package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/AlexEduSantos/go-auth/internal/handlers"
	"github.com/AlexEduSantos/go-auth/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
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
	authHandler := handlers.NewAuthHandler(userRepo)

	// Configura as rotas
	mux := http.NewServeMux()
	mux.HandleFunc("/api/register", authHandler.Register)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("API rodando perfeitamente!"))
	})

	fmt.Println("Servidor rodando na porta 8080...")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("Erro ao iniciar servidor: %v", err)
	}
}
