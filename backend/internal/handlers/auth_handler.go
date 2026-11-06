package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/AlexEduSantos/go-auth/internal/models"
	"github.com/AlexEduSantos/go-auth/internal/repository"
	"golang.org/x/crypto/bcrypt"

	"time"

	"crypto/rand"
	"encoding/hex"

	"github.com/golang-jwt/jwt/v5"
)

const SessionDuration = 24 * time.Hour // Duração de 24 horas

type AuthHandler struct {
	userRepo    *repository.UserRepository
	sessionRepo *repository.SessionRepository
}

func NewAuthHandler(userRepo *repository.UserRepository, sessionRepo *repository.SessionRepository) *AuthHandler {
	return &AuthHandler{userRepo: userRepo, sessionRepo: sessionRepo}
}

type RegisterRequest struct {
	Username string          `json:"username"`
	Name     string          `json:"name"`
	Email    string          `json:"email"`
	Password string          `json:"password"`
	Role     models.UserRole `json:"role"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Payload JSON inválido", http.StatusBadRequest)
		return
	}

	// Validação simples
	if req.Username == "" || req.Email == "" || req.Password == "" || req.Name == "" {
		http.Error(w, "Preencha todos os campos obrigatórios", http.StatusBadRequest)
		return
	}

	// Gera o hash seguro da senha (bcrypt)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Erro ao processar senha", http.StatusInternalServerError)
		return
	}

	// Define role padrão caso não venha informada
	role := req.Role
	if role == "" {
		role = models.RoleUser
	}

	user := &models.User{
		Username: req.Username,
		Name:     req.Name,
		Email:    req.Email,
		Password: string(hashedPassword),
		Role:     role,
	}

	// Salva no banco de dados
	err = h.userRepo.Create(r.Context(), user)
	if err != nil {
		// Em produção tratamos o erro de unique constraint (duplicidade de email/username)
		http.Error(w, "Erro ao registrar usuário (email ou username já podem existir)", http.StatusConflict)
		return
	}

	// Retorna o usuário criado com status 201 (Created)
	// Nota: O campo Password tem a tag `json:"-"` no model, logo não será exposto na resposta
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

var jwtSecret = []byte("sua_chave_secreta_super_segura_aqui")

type LoginRequest struct {
	Identifier string `json:"identifier"` // Pode ser email ou username
	Password   string `json:"password"`
}

type LoginResponse struct {
	Token string       `json:"token"`
	User  *models.User `json:"user"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Payload JSON inválido", http.StatusBadRequest)
		return
	}

	if req.Identifier == "" || req.Password == "" {
		http.Error(w, "Informe o utilizador/email e a senha", http.StatusBadRequest)
		return
	}

	// Busca o utilizador no banco pelo email ou username
	user, err := h.userRepo.FindByIdentifier(r.Context(), req.Identifier)
	if err != nil {
		http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
		return
	}

	// Compara a senha enviada com o hash bcrypt armazenado
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
		return
	}

	// Gera o Token JWT (expira em 24 horas)
	claims := jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"role":  user.Role,
		"exp":   time.Now().Add(SessionDuration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Erro ao gerar token de autenticação", http.StatusInternalServerError)
		return
	}

	// Responde com o token e os dados do utilizador
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LoginResponse{
		Token: tokenString,
		User:  user,
	})

	sid, err := generateRandomToken() // reutilizando a função de token aleatório
	if err != nil {
		http.Error(w, "Erro ao criar sessão", http.StatusInternalServerError)
		return
	}

	// Estrutura os dados que deseja guardar na sessão (JSON)
	sessionDataMap := map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
	}
	sessionJSON, _ := json.Marshal(sessionDataMap)
	expiresAt := time.Now().Add(SessionDuration)

	// Salva na tabela session do PostgreSQL
	err = h.sessionRepo.Save(r.Context(), sid, sessionJSON, expiresAt)
	if err != nil {
		http.Error(w, "Erro ao salvar sessão no banco", http.StatusInternalServerError)
		return
	}
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Exemplo recebendo o SID via header ou payload JSON
	var req struct {
		SID string `json:"sid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SID == "" {
		http.Error(w, "SID inválido", http.StatusBadRequest)
		return
	}

	err := h.sessionRepo.Delete(r.Context(), req.SID)
	if err != nil {
		http.Error(w, "Erro ao encerrar sessão", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Sessão encerrada com sucesso!",
	})
}

// Função auxiliar para gerar um token aleatório seguro
func generateRandomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// 1. Solicitar recuperação de senha
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, "Payload inválido ou email não fornecido", http.StatusBadRequest)
		return
	}

	// Gera um token aleatório e define expiração para 1 hora
	token, err := generateRandomToken()
	if err != nil {
		http.Error(w, "Erro ao gerar token de recuperação", http.StatusInternalServerError)
		return
	}
	expiresAt := time.Now().Add(time.Hour * 1)

	// Salva no banco (se o email não existir, por segurança não revelamos ao cliente, retornamos sucesso genérico)
	_ = h.userRepo.SavePasswordResetToken(r.Context(), req.Email, token, expiresAt)

	// NOTA REAL: Aqui você integraria o envio do e-mail com o link contendo o token (ex: /reset-password?token=XYZ)
	// Para fins de desenvolvimento/teste, podemos retornar o token na resposta:
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message":     "Se o email estiver registado, instruções foram enviadas.",
		"debug_token": token, // Remova esta linha em produção por segurança!
	})
}

// 2. Redefinir a senha usando o token
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" || req.NewPassword == "" {
		http.Error(w, "Dados incompletos ou inválidos", http.StatusBadRequest)
		return
	}

	// Procura o usuário pelo token válido e não expirado
	user, err := h.userRepo.FindByResetToken(r.Context(), req.Token)
	if err != nil {
		http.Error(w, "Token inválido ou expirado", http.StatusBadRequest)
		return
	}

	// Gera o hash da nova senha
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Erro ao processar nova senha", http.StatusInternalServerError)
		return
	}

	// Atualiza a senha e limpa o token no banco
	err = h.userRepo.UpdatePasswordAndClearToken(r.Context(), user.ID, string(hashedPassword))
	if err != nil {
		http.Error(w, "Erro ao atualizar a senha", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Senha redefinida com sucesso!",
	})
}
