package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"E-mail válido", "usuario@exemplo.com", false},
		{"E-mail com subdomínio", "nome.sobrenome@empresa.com.br", false},
		{"Sem arroba", "usuarioexemplo.com", true},
		{"Sem domínio válido (sem ponto)", "usuario@localhost", true},
		{"Com nome de exibição embutido", "Alex <alex@exemplo.com>", true},
		{"Vazio", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEmail(tc.email)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateEmail(%q) error = %v, wantErr %v", tc.email, err, tc.wantErr)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"Username válido", "alex_santos.99", false},
		{"Muito curto", "ab", true},
		{"Com espaço", "alex santos", true},
		{"Com arroba", "alex@santos", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUsername(tc.username)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateUsername(%q) error = %v, wantErr %v", tc.username, err, tc.wantErr)
			}
		})
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"Senha forte válida", "Forte@123", false},
		{"Menos de 8 caracteres", "Ab1@cur", true},
		{"Sem letra maiúscula", "fraca@1234", true},
		{"Sem letra minúscula", "FRACA@1234", true},
		{"Sem número", "Fraca@Senha", true},
		{"Sem símbolo especial", "Fraca12345", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePasswordStrength(tc.password)
			if (err != nil) != tc.wantErr {
				t.Errorf("validatePasswordStrength(%q) error = %v, wantErr %v", tc.password, err, tc.wantErr)
			}
		})
	}
}

func TestRegisterHandler_ValidationRejections(t *testing.T) {
	handler := NewAuthHandler(nil, nil)

	tests := []struct {
		name       string
		payload    string
		wantStatus int
	}{
		{
			name:       "Rejeita e-mail inválido antes do bcrypt/DB",
			payload:    `{"username":"alex123","name":"Alex","email":"email-invalido","password":"SenhaForte@123"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "Rejeita senha fraca antes do bcrypt/DB",
			payload:    `{"username":"alex123","name":"Alex","email":"alex@exemplo.com","password":"123"}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewBufferString(tc.payload))
			rec := httptest.NewRecorder()

			handler.Register(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, esperado %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}
