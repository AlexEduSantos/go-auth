package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/AlexEduSantos/go-auth/internal/logger"
)

// responseWriterInterceptor intercepta o status HTTP retornado
type responseWriterInterceptor struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterInterceptor) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// RequestLogger faz o log estruturado de cada requisição HTTP
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignora rotas de healthcheck para não poluir o banco de dados
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		interceptor := &responseWriterInterceptor{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(interceptor, r)

		duration := time.Since(start)

		attrs := []any{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", interceptor.statusCode),
			slog.Duration("latency", duration),
			slog.String("client_ip", r.RemoteAddr),
		}

		// Ajusta o nível do log conforme o status HTTP
		switch {
		case interceptor.statusCode >= 500:
			logger.Log.Error("Erro interno na requisição HTTP", attrs...)
		case interceptor.statusCode >= 400:
			logger.Log.Warn("Requisição HTTP rejeitada ou inválida", attrs...)
		default:
			logger.Log.Info("Requisição HTTP tratada", attrs...)
		}
	})
}
