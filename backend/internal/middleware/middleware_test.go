package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AlexEduSantos/go-auth/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

func generateTestToken(userID, sid string, role models.UserRole) string {
	claims := jwt.MapClaims{
		"sid":  sid,
		"sub":  userID,
		"role": string(role),
		"exp":  time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString(jwtSecret)
	return signed
}

func TestAuthMiddleware_And_RequireRole(t *testing.T) {
	protectedAdminHandler := AuthMiddleware(RequireRole(func(w http.ResponseWriter, r *http.Request) {
		userID, _ := r.Context().Value(UserIDKey).(string)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK:" + userID))
	}, models.RoleAdmin))

	t.Run("Bloqueia requisição sem cookie (401)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
		rec := httptest.NewRecorder()

		protectedAdminHandler(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("esperado 401, obteve %d", rec.Code)
		}
	})

	t.Run("Bloqueia usuário com role insuficiente (403)", func(t *testing.T) {
		tokenStr := generateTestToken("user-1", "sid-1", models.RoleUser)
		req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: tokenStr})
		rec := httptest.NewRecorder()

		protectedAdminHandler(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("esperado 403, obteve %d", rec.Code)
		}
	})

	t.Run("Permite usuário com role ADMIN e injeta dados no Context (200)", func(t *testing.T) {
		tokenStr := generateTestToken("admin-42", "sid-42", models.RoleAdmin)
		req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: tokenStr})
		rec := httptest.NewRecorder()

		protectedAdminHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("esperado 200, obteve %d", rec.Code)
		}
		if rec.Body.String() != "OK:admin-42" {
			t.Errorf("body inesperado: %s", rec.Body.String())
		}
	})
}

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/qualquer", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Content-Security-Policy":   "default-src 'self'",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}

	for header, expected := range expectedHeaders {
		if got := rec.Header().Get(header); got != expected {
			t.Errorf("header %s = %q, esperado %q", header, got, expected)
		}
	}
}

func TestCSRFMiddleware_DoubleSubmitCookie(t *testing.T) {
	handler := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Bloqueia POST protegido sem cookie/header CSRF (403)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("esperado 403 Forbidden, obteve %d", rec.Code)
		}
	})

	t.Run("Bloqueia POST protegido quando cookie e header X-CSRF-Token divergem (403)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "token-a"})
		req.Header.Set(CSRFHeaderName, "token-b")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("esperado 403 Forbidden, obteve %d", rec.Code)
		}
	})

	t.Run("Permite POST protegido quando cookie csrf_token e header X-CSRF-Token coincidem (200)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "token-seguro-123"})
		req.Header.Set(CSRFHeaderName, "token-seguro-123")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("esperado 200 OK, obteve %d", rec.Code)
		}
	})
}

