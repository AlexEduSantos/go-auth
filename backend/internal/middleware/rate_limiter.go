package middleware

import (
	"net"
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

type IPRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  sync.RWMutex
	r   rate.Limit
	b   int
}

// NewIPRateLimiter cria um limitador.
// r: taxa de requisições por segundo (ex: 1 requisição a cada 2 segundos -> 0.5)
// b: burst (máximo de requisições em rajada permitidas)
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
		r:   r,
		b:   b,
	}
}

func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(i.r, i.b)
		i.ips[ip] = limiter
	}

	return limiter
}

func (i *IPRateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extrai o IP real do cliente (considerando proxies se necessário, aqui usamos RemoteAddr)
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		limiter := i.GetLimiter(ip)
		if !limiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "Muitas requisições. Tente novamente mais tarde."}`))
			return
		}

		next(w, r)
	}
}
