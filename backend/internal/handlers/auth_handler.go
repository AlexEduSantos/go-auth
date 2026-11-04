package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/AlexEduSantos/go-auth/internal/models"
	"github.com/AlexEduSantos/go-auth/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	userRepo *repository.UserRepository
}

func NewAuthHandler(userRepo *repository.UserRepository) *AuthHandler {
	return &AuthHandler{userRepo: userRepo}
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
