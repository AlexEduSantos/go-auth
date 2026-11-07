package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/AlexEduSantos/go-auth/internal/middleware"
	"github.com/AlexEduSantos/go-auth/internal/models"
	"github.com/AlexEduSantos/go-auth/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	AccessTokenDuration  = 15 * time.Minute   // Access Token curto (15 minutos)
	RefreshTokenDuration = 7 * 24 * time.Hour // Refresh Token / Sessão longa (7 dias)
	SessionDuration      = RefreshTokenDuration
)

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

// Register cria uma nova conta de usuário.
// @Summary      Registrar novo usuário
// @Description  Valida os dados de entrada, verifica a força da senha e cria um novo usuário com senha criptografada (bcrypt).
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request  body      RegisterRequest  true  "Dados de registro"
// @Success      201      {object}  models.User
// @Failure      400      {string}  string  "Dados inválidos ou senha fraca"
// @Failure      409      {string}  string  "Email ou username já existente"
// @Router       /api/register [post]
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

	// Normaliza os campos de texto
	req.Username = strings.TrimSpace(req.Username)
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// 1. Validação de presença dos campos obrigatórios
	if req.Username == "" || req.Email == "" || req.Password == "" || req.Name == "" {
		http.Error(w, "Preencha todos os campos obrigatórios", http.StatusBadRequest)
		return
	}

	// 2. Validação rigorosa de username, e-mail e força da senha (antes do hash bcrypt)
	if err := validateUsername(req.Username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateEmail(req.Email); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validatePasswordStrength(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		slog.Warn("Falha ao registrar usuário (conflito)",
			slog.String("username", req.Username),
			slog.String("email", req.Email),
			slog.String("ip", r.RemoteAddr),
		)
		// Em produção tratamos o erro de unique constraint (duplicidade de email/username)
		http.Error(w, "Erro ao registrar usuário (email ou username já podem existir)", http.StatusConflict)
		return
	}

	slog.Info("Novo usuário registrado",
		slog.String("user_id", user.ID),
		slog.String("username", user.Username),
		slog.String("role", string(user.Role)),
	)

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

// Login autentica o usuário (via email ou username) e emite os cookies HttpOnly (auth_token e refresh_token).
// @Summary      Autenticar usuário (Login híbrido)
// @Description  Autentica via email ou username, cria sessão no PostgreSQL e define cookies HttpOnly para Access Token (15m) e Refresh Token (7d).
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request  body      LoginRequest  true  "Credenciais de login"
// @Success      200      {object}  map[string]interface{}
// @Failure      400      {string}  string  "Payload ou formato inválido"
// @Failure      401      {string}  string  "Credenciais inválidas"
// @Router       /api/login [post]
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

	req.Identifier = strings.TrimSpace(req.Identifier)
	if req.Identifier == "" || req.Password == "" {
		http.Error(w, "Informe o utilizador/email e a senha", http.StatusBadRequest)
		return
	}

	// Login híbrido: se contiver "@", valida e normaliza como e-mail; caso contrário, valida como username
	if strings.Contains(req.Identifier, "@") {
		req.Identifier = strings.ToLower(req.Identifier)
		if err := validateEmail(req.Identifier); err != nil {
			http.Error(w, "Formato de e-mail inválido", http.StatusBadRequest)
			return
		}
	} else {
		if err := validateUsername(req.Identifier); err != nil {
			http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
			return
		}
	}

	// Busca o utilizador no banco pelo email ou username
	user, err := h.userRepo.FindByIdentifier(r.Context(), req.Identifier)
	if err != nil {
		slog.Warn("Tentativa de login com usuário inexistente",
			slog.String("identifier", req.Identifier),
			slog.String("ip", r.RemoteAddr),
		)
		http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
		return
	}

	// Compara a senha enviada com o hash bcrypt armazenado
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		slog.Warn("Tentativa de login com senha incorreta",
			slog.String("user_id", user.ID),
			slog.String("identifier", req.Identifier),
			slog.String("ip", r.RemoteAddr),
		)
		http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
		return
	}

	// 1. Gera o SID (Refresh Token) e salva a sessão no banco primeiro (validade de 7 dias)
	sid, err := generateRandomToken()
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
	refreshExpiresAt := time.Now().Add(RefreshTokenDuration)

	// Salva na tabela session do PostgreSQL
	err = h.sessionRepo.Save(r.Context(), sid, sessionJSON, refreshExpiresAt)
	if err != nil {
		http.Error(w, "Erro ao salvar sessão no banco", http.StatusInternalServerError)
		return
	}

	// 2. Gera o Access Token JWT de curta duração (15 minutos) incluindo o "sid" nas claims
	accessExpiresAt := time.Now().Add(AccessTokenDuration)
	claims := jwt.MapClaims{
		"sid":   sid,
		"sub":   user.ID,
		"email": user.Email,
		"role":  user.Role,
		"exp":   accessExpiresAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Erro ao gerar token de autenticação", http.StatusInternalServerError)
		return
	}

	// 3. Define os cookies HttpOnly (Access Token curto + Refresh Token longo)
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,                 // Impede acesso via JavaScript (Proteção contra XSS)
		Secure:   false,                // Mude para true em produção quando usar HTTPS
		SameSite: http.SameSiteLaxMode, // Proteção básica contra CSRF
		Expires:  accessExpiresAt,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Expires:  refreshExpiresAt,
	})

	// Emite também o cookie csrf_token (Double Submit Cookie) para proteger requisições subsequentes
	csrfToken, _ := middleware.SetCSRFCookie(w)

	slog.Info("Login efetuado com sucesso",
		slog.String("user_id", user.ID),
		slog.String("role", string(user.Role)),
		slog.String("sid", sid),
		slog.String("ip", r.RemoteAddr),
	)

	// Retorna os dados do usuário e o csrf_token (para facilitar o uso no header X-CSRF-Token)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Login efetuado com sucesso!",
		"user":       user,
		"csrf_token": csrfToken,
	})
}

// Refresh implementa a estratégia de Refresh Token Rotation.
// @Summary      Renovar Access Token (Refresh Token Rotation)
// @Description  Valida o cookie refresh_token no banco, invalida o SID antigo, gera um novo SID (rotação) e emite novos cookies auth_token (15m) e refresh_token (7d).
// @Tags         Auth
// @Produce      json
// @Success      200  {object}  map[string]string
// @Failure      401  {string}  string  "Refresh token ausente, inválido ou expirado"
// @Router       /api/refresh [post]
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("refresh_token")
	if err != nil || cookie.Value == "" {
		http.Error(w, "Não autorizado: Refresh token ausente", http.StatusUnauthorized)
		return
	}
	oldSID := cookie.Value

	// 1. Verifica se a sessão existe e está ativa no PostgreSQL
	sessBytes, err := h.sessionRepo.Find(r.Context(), oldSID)
	if err != nil {
		slog.Warn("Tentativa de refresh com sessão inválida ou expirada",
			slog.String("old_sid", oldSID),
			slog.String("ip", r.RemoteAddr),
		)
		http.Error(w, "Não autorizado: Sessão inválida ou expirada", http.StatusUnauthorized)
		return
	}

	var sessData map[string]string
	if err := json.Unmarshal(sessBytes, &sessData); err != nil {
		http.Error(w, "Erro ao processar dados da sessão", http.StatusInternalServerError)
		return
	}

	// 2. Token Rotation: invalida o Refresh Token antigo imediatamente e cria um novo
	_ = h.sessionRepo.Delete(r.Context(), oldSID)

	newSID, err := generateRandomToken()
	if err != nil {
		http.Error(w, "Erro ao rotacionar sessão", http.StatusInternalServerError)
		return
	}

	refreshExpiresAt := time.Now().Add(RefreshTokenDuration)
	if err := h.sessionRepo.Save(r.Context(), newSID, sessBytes, refreshExpiresAt); err != nil {
		http.Error(w, "Erro ao salvar nova sessão", http.StatusInternalServerError)
		return
	}

	// 3. Emite um novo Access Token JWT de 15 minutos
	accessExpiresAt := time.Now().Add(AccessTokenDuration)
	claims := jwt.MapClaims{
		"sid":   newSID,
		"sub":   sessData["user_id"],
		"email": sessData["email"],
		"role":  sessData["role"],
		"exp":   accessExpiresAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Erro ao gerar novo access token", http.StatusInternalServerError)
		return
	}

	// 4. Atualiza ambos os cookies HttpOnly
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Expires:  accessExpiresAt,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    newSID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Expires:  refreshExpiresAt,
	})

	// Rotaciona também o CSRF token
	csrfToken, _ := middleware.SetCSRFCookie(w)

	slog.Info("Tokens rotacionados com sucesso (Refresh)",
		slog.String("user_id", sessData["user_id"]),
		slog.String("old_sid", oldSID),
		slog.String("new_sid", newSID),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message":    "Token renovado com sucesso!",
		"csrf_token": csrfToken,
	})
}

// Logout encerra a sessão no banco e limpa os cookies de autenticação.
// @Summary      Encerrar sessão (Logout)
// @Description  Extrai o SID do cookie, remove a sessão ativa do PostgreSQL e expira os cookies auth_token e refresh_token.
// @Tags         Auth
// @Produce      json
// @Success      200  {object}  map[string]string
// @Failure      401  {string}  string  "Não autorizado"
// @Router       /api/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	// 1. Extrai o cookie com o token JWT
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Não autorizado: Cookie ausente", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Erro ao ler cookie", http.StatusBadRequest)
		return
	}

	// 2. Faz o parse e valida o token JWT para extrair as claims (ex: sid)
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Token inválido ou expirado", http.StatusUnauthorized)
		return
	}

	// 3. Extrai o SID de dentro das claims do JWT e deleta a sessão no banco
	if sid, ok := claims["sid"].(string); ok && sid != "" {
		if err := h.sessionRepo.Delete(r.Context(), sid); err != nil {
			slog.Error("Erro ao encerrar sessão no banco",
				slog.String("sid", sid),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Erro ao encerrar sessão", http.StatusInternalServerError)
			return
		}
		slog.Info("Sessão encerrada (Logout)",
			slog.Any("user_id", claims["sub"]),
			slog.String("sid", sid),
		)
	}

	// 4. Limpa/expira ambos os cookies no navegador (auth_token e refresh_token)
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // true em produção (HTTPS)
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Expira o cookie imediatamente
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     middleware.CSRFCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Sessão encerrada com sucesso!",
	})
}

// Funções auxiliares de validação rigorosa de entrada e força de senha
func validateEmail(email string) error {
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return errors.New("Formato de e-mail inválido")
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 || !strings.Contains(parts[1], ".") || strings.HasPrefix(parts[1], ".") || strings.HasSuffix(parts[1], ".") {
		return errors.New("Domínio de e-mail inválido")
	}

	return nil
}

func validateUsername(username string) error {
	length := utf8.RuneCountInString(username)
	if length < 3 || length > 50 {
		return errors.New("O username deve ter entre 3 e 50 caracteres")
	}

	for _, r := range username {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_' && r != '-' && r != '.' {
			return errors.New("O username pode conter apenas letras, números, '_', '-' ou '.'")
		}
	}

	return nil
}

func validatePasswordStrength(password string) error {
	if utf8.RuneCountInString(password) < 8 {
		return errors.New("A senha deve ter no mínimo 8 caracteres")
	}
	if len(password) > 72 {
		return errors.New("A senha deve ter no máximo 72 bytes")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsNumber(r):
			hasNumber = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return errors.New("A senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um símbolo especial")
	}

	return nil
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
// @Summary      Solicitar recuperação de senha
// @Description  Gera um token seguro de recuperação com validade de 1 hora para o e-mail informado.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request  body      ForgotPasswordRequest  true  "E-mail de recuperação"
// @Success      200      {object}  map[string]string
// @Failure      400      {string}  string  "E-mail inválido"
// @Router       /api/forgot-password [post]
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Payload inválido", http.StatusBadRequest)
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if err := validateEmail(req.Email); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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

	slog.Info("Solicitação de recuperação de senha recebida",
		slog.String("email", req.Email),
		slog.String("ip", r.RemoteAddr),
	)

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
// @Summary      Redefinir senha
// @Description  Valida o token de recuperação e a força da nova senha, atualizando o hash bcrypt no banco.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request  body      ResetPasswordRequest  true  "Token e nova senha"
// @Success      200      {object}  map[string]string
// @Failure      400      {string}  string  "Token inválido/expirado ou senha fraca"
// @Router       /api/reset-password [post]
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Token) == "" || req.NewPassword == "" {
		http.Error(w, "Dados incompletos ou inválidos", http.StatusBadRequest)
		return
	}

	// Valida a força da nova senha antes de consultar o banco ou gerar o hash bcrypt
	if err := validatePasswordStrength(req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		slog.Error("Erro ao atualizar senha no ResetPassword",
			slog.String("user_id", user.ID),
			slog.String("error", err.Error()),
		)
		http.Error(w, "Erro ao atualizar a senha", http.StatusInternalServerError)
		return
	}

	slog.Info("Senha redefinida com sucesso",
		slog.String("user_id", user.ID),
		slog.String("ip", r.RemoteAddr),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Senha redefinida com sucesso!",
	})
}
