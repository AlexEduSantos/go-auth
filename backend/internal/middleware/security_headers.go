package middleware

import "net/http"

// SecurityHeaders injeta cabeçalhos HTTP de segurança padrão em todas as respostas da API
// para proteger contra Clickjacking, MIME-sniffing, XSS e forçar HTTPS (HSTS).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Na rota visual do Swagger UI permitimos o carregamento do bundle CSS/JS do unpkg;
		// em todos os demais endpoints da API aplicamos a política estrita default-src 'self'.
		if r.URL.Path == "/swagger" {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com")
		} else {
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
		}

		next.ServeHTTP(w, r)
	})
}
