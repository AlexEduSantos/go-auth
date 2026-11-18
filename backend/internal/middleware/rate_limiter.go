package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type IPRateLimiter struct {
	ips map[string]*clientLimiter
	mu  sync.Mutex
	r   rate.Limit
	b   int
}

// NewIPRateLimiter cria um limitador com rotina automática de limpeza de IPs inativos (evita Memory Leak).
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	rl := &IPRateLimiter{
		ips: make(map[string]*clientLimiter),
		r:   r,
		b:   b,
	}

	// Goroutine em background que remove IPs inativos há mais de 10 minutos
	go rl.cleanupStaleIPs(5*time.Minute, 10*time.Minute)

	return rl
}

func (i *IPRateLimiter) cleanupStaleIPs(interval, maxAge time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		i.mu.Lock()
		for ip, client := range i.ips {
			if time.Since(client.lastSeen) > maxAge {
				delete(i.ips, ip)
			}
		}
		i.mu.Unlock()
	}
}

func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	client, exists := i.ips[ip]
	if !exists {
		limiter := rate.NewLimiter(i.r, i.b)
		i.ips[ip] = &clientLimiter{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}

	client.lastSeen = time.Now()
	return client.limiter
}

func (i *IPRateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		limiter := i.GetLimiter(ip)
		if !limiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error": "Muitas requisições. Tente novamente mais tarde."}`))
			return
		}

		next(w, r)
	}
}
