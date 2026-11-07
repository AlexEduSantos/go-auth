package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

const (
	CSRFCookieName = "csrf_token"
	CSRFHeaderName = "X-CSRF-Token"
)

// GenerateCSRFToken gera um token aleatório criptograficamente seguro de 32 bytes (64 caracteres hex)
func GenerateCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// SetCSRFCookie define o cookie csrf_token (HttpOnly: false para que o frontend possa lê-lo
// e enviá-lo no cabeçalho X-CSRF-Token no padrão Double Submit Cookie) e também o expõe no header.
func SetCSRFCookie(w http.ResponseWriter) (string, error) {
	token, err := GenerateCSRFToken()
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // O frontend precisa ler este cookie para enviá-lo no header X-CSRF-Token
		Secure:   false, // Mude para true em produção (HTTPS)
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	})
	w.Header().Set(CSRFHeaderName, token)
	return token, nil
}

// CSRFTokenHandler é um endpoint (GET /api/csrf-token) para que o frontend possa obter/renovar
// um CSRF token explicitamente caso necessário.
func CSRFTokenHandler(w http.ResponseWriter, r *http.Request) {
	token, err := SetCSRFCookie(w)
	if err != nil {
		http.Error(w, "Erro ao gerar CSRF token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"csrf_token": token,
	})
}

// isCSRFFreePath define rotas públicas iniciais que ainda não possuem sessão/cookie ativo
func isCSRFFreePath(path string) bool {
	switch path {
	case "/api/login", "/api/register", "/api/forgot-password", "/api/reset-password":
		return true
	default:
		return false
	}
}

// CSRFMiddleware implementa o padrão Double Submit Cookie para proteger rotas que modificam estado
// (POST, PUT, PATCH, DELETE) contra ataques Cross-Site Request Forgery (CSRF).
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Métodos seguros (GET, HEAD, OPTIONS) não alteram estado
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			if _, err := r.Cookie(CSRFCookieName); err == http.ErrNoCookie {
				_, _ = SetCSRFCookie(w)
			}
			next.ServeHTTP(w, r)
			return
		}

		// Rotas públicas de entrada inicial (Login, Register, etc.)
		if isCSRFFreePath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Validação Double Submit Cookie: o valor do cookie csrf_token deve coincidir
		// em tempo constante com o valor enviado no cabeçalho X-CSRF-Token.
		cookie, err := r.Cookie(CSRFCookieName)
		if err != nil || cookie.Value == "" {
			slog.Warn("Requisição bloqueada por CSRF: cookie csrf_token ausente",
				slog.String("path", r.URL.Path),
				slog.String("ip", r.RemoteAddr),
			)
			http.Error(w, "Proibido: CSRF token ausente no cookie", http.StatusForbidden)
			return
		}

		headerToken := r.Header.Get(CSRFHeaderName)
		if headerToken == "" {
			slog.Warn("Requisição bloqueada por CSRF: cabeçalho X-CSRF-Token ausente",
				slog.String("path", r.URL.Path),
				slog.String("ip", r.RemoteAddr),
			)
			http.Error(w, "Proibido: Cabeçalho X-CSRF-Token ausente", http.StatusForbidden)
			return
		}

		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(headerToken)) != 1 {
			slog.Warn("Requisição bloqueada por CSRF: token inválido/divergente",
				slog.String("path", r.URL.Path),
				slog.String("ip", r.RemoteAddr),
			)
			http.Error(w, "Proibido: CSRF token inválido", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
