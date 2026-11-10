package docs

import (
	"net/http"
)

const openAPISpec = `{
  "openapi": "3.0.3",
  "info": {
    "title": "Go-Auth API",
    "description": "API de Autenticação e Autorização em Go com JWT (HttpOnly Cookies), Refresh Token Rotation, RBAC e Logs Estruturados (slog + PostgreSQL).",
    "version": "1.0.0"
  },
  "servers": [
    {
      "url": "http://localhost:8080",
      "description": "Servidor Local"
    }
  ],
  "components": {
    "securitySchemes": {
      "cookieAuth": {
        "type": "apiKey",
        "in": "cookie",
        "name": "auth_token"
      },
      "refreshCookie": {
        "type": "apiKey",
        "in": "cookie",
        "name": "refresh_token"
      },
      "csrfHeader": {
        "type": "apiKey",
        "in": "header",
        "name": "X-CSRF-Token"
      }
    },
    "schemas": {
      "RegisterRequest": {
        "type": "object",
        "required": ["username", "name", "email", "password"],
        "properties": {
          "username": { "type": "string", "example": "alex_santos" },
          "name": { "type": "string", "example": "Alex Santos" },
          "email": { "type": "string", "format": "email", "example": "alex@exemplo.com" },
          "password": { "type": "string", "format": "password", "example": "SenhaForte@123" },
          "role": { "type": "string", "enum": ["ADMIN", "PUBLISHER", "MANAGER", "USER"], "example": "USER" }
        }
      },
      "LoginRequest": {
        "type": "object",
        "required": ["identifier", "password"],
        "properties": {
          "identifier": { "type": "string", "description": "Email ou Username", "example": "alex@exemplo.com" },
          "password": { "type": "string", "format": "password", "example": "SenhaForte@123" }
        }
      },
      "MagicLinkRequest": {
        "type": "object",
        "required": ["identifier"],
        "properties": {
          "identifier": { "type": "string", "description": "Email ou Username", "example": "alex@exemplo.com" }
        }
      },
      "VerifyOTPRequest": {
        "type": "object",
        "properties": {
          "identifier": { "type": "string", "description": "Email ou Username", "example": "alex@exemplo.com" },
          "code": { "type": "string", "description": "Código numérico de 6 dígitos (OTP)", "example": "482910" },
          "token": { "type": "string", "description": "Token do Magic Link (alternativa ao OTP)" }
        }
      },
      "ForgotPasswordRequest": {
        "type": "object",
        "required": ["email"],
        "properties": {
          "email": { "type": "string", "format": "email", "example": "alex@exemplo.com" }
        }
      },
      "ResetPasswordRequest": {
        "type": "object",
        "required": ["token", "new_password"],
        "properties": {
          "token": { "type": "string", "example": "a1b2c3d4..." },
          "new_password": { "type": "string", "format": "password", "example": "NovaSenha@123" }
        }
      },
      "User": {
        "type": "object",
        "properties": {
          "id": { "type": "string", "format": "uuid" },
          "username": { "type": "string" },
          "name": { "type": "string" },
          "email": { "type": "string" },
          "role": { "type": "string" },
          "is_verified": { "type": "boolean" },
          "created_at": { "type": "string", "format": "date-time" },
          "updated_at": { "type": "string", "format": "date-time" }
        }
      }
    }
  },
  "paths": {
    "/api/csrf-token": {
      "get": {
        "tags": ["Security"],
        "summary": "Obter CSRF Token (Double Submit Cookie)",
        "description": "Gera um novo token CSRF, define o cookie csrf_token e retorna o valor no corpo JSON e no header X-CSRF-Token.",
        "responses": {
          "200": { "description": "CSRF token gerado com sucesso" }
        }
      }
    },
    "/api/register": {
      "post": {
        "tags": ["Auth"],
        "summary": "Registrar novo usuário",
        "description": "Valida formato de e-mail, username e força da senha antes de criar o hash bcrypt.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/RegisterRequest" }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Usuário criado com sucesso",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/User" }
              }
            }
          },
          "400": { "description": "Dados inválidos ou senha fraca" },
          "409": { "description": "Conflito: Email ou username já existem" }
        }
      }
    },
    "/api/verify": {
      "get": {
        "tags": ["Auth"],
        "summary": "Confirmar e-mail de registo (Double Opt-In)",
        "description": "Valida o token de verificação enviado por e-mail (?token=XYZ) e atualiza is_verified = true no utilizador.",
        "parameters": [
          {
            "name": "token",
            "in": "query",
            "required": true,
            "schema": { "type": "string" }
          }
        ],
        "responses": {
          "200": { "description": "E-mail confirmado com sucesso" },
          "400": { "description": "Token ausente, inválido ou expirado" }
        }
      },
      "post": {
        "tags": ["Auth"],
        "summary": "Confirmar e-mail de registo via JSON (Double Opt-In)",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["token"],
                "properties": {
                  "token": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "E-mail confirmado com sucesso" },
          "400": { "description": "Token ausente, inválido ou expirado" }
        }
      }
    },
    "/api/login": {
      "post": {
        "tags": ["Auth"],
        "summary": "Login híbrido (Email ou Username)",
        "description": "Autentica o usuário e define cookies HttpOnly: auth_token (15 min) e refresh_token (7 dias).",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/LoginRequest" }
            }
          }
        },
        "responses": {
          "200": { "description": "Login efetuado com sucesso" },
          "400": { "description": "Formato inválido" },
          "401": { "description": "Credenciais inválidas" },
          "403": { "description": "E-mail ainda não confirmado (Double Opt-In)" }
        }
      }
    },
    "/api/auth/magic-link": {
      "post": {
        "tags": ["Passwordless"],
        "summary": "Solicitar Código OTP (6 dígitos) ou Magic Link",
        "description": "Gera um código numérico de 6 dígitos (OTP) e um Magic Link com validade de 10 minutos associados ao utilizador.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/MagicLinkRequest" }
            }
          }
        },
        "responses": {
          "200": { "description": "Código OTP / Magic Link gerado com sucesso" },
          "400": { "description": "Formato de e-mail/username inválido" }
        }
      }
    },
    "/api/auth/verify-otp": {
      "post": {
        "tags": ["Passwordless"],
        "summary": "Validar Código OTP / Magic Link e Autenticar",
        "description": "Valida o código de 6 dígitos (ou token), limpa o código usado no banco e emite a sessão com cookies HttpOnly (auth_token e refresh_token).",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/VerifyOTPRequest" }
            }
          }
        },
        "responses": {
          "200": { "description": "Autenticação Passwordless efetuada com sucesso" },
          "400": { "description": "Dados incompletos" },
          "401": { "description": "Código OTP ou Magic Link inválido ou expirado" }
        }
      },
      "get": {
        "tags": ["Passwordless"],
        "summary": "Autenticar clicando diretamente no Magic Link",
        "parameters": [
          {
            "name": "token",
            "in": "query",
            "required": true,
            "schema": { "type": "string" }
          }
        ],
        "responses": {
          "200": { "description": "Autenticação Passwordless efetuada com sucesso" },
          "401": { "description": "Magic Link inválido ou expirado" }
        }
      }
    },
    "/api/refresh": {
      "post": {
        "tags": ["Auth"],
        "summary": "Renovar Access Token (Refresh Token Rotation)",
        "description": "Lê o cookie refresh_token, invalida o SID anterior no banco, cria um novo SID e emite novos cookies auth_token, refresh_token e csrf_token.",
        "security": [{ "refreshCookie": [], "csrfHeader": [] }],
        "responses": {
          "200": { "description": "Token renovado com sucesso" },
          "401": { "description": "Refresh token ausente, inválido ou expirado" },
          "403": { "description": "CSRF token ausente ou inválido" }
        }
      }
    },
    "/api/logout": {
      "post": {
        "tags": ["Auth"],
        "summary": "Encerrar sessão (Logout)",
        "description": "Remove a sessão ativa do PostgreSQL e expira os cookies auth_token, refresh_token e csrf_token.",
        "security": [{ "cookieAuth": [], "csrfHeader": [] }],
        "responses": {
          "200": { "description": "Sessão encerrada com sucesso" },
          "401": { "description": "Não autorizado" },
          "403": { "description": "CSRF token ausente ou inválido" }
        }
      }
    },
    "/api/forgot-password": {
      "post": {
        "tags": ["Auth"],
        "summary": "Solicitar recuperação de senha",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/ForgotPasswordRequest" }
            }
          }
        },
        "responses": {
          "200": { "description": "Instruções enviadas" },
          "400": { "description": "E-mail inválido" }
        }
      }
    },
    "/api/reset-password": {
      "post": {
        "tags": ["Auth"],
        "summary": "Redefinir senha com token",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/ResetPasswordRequest" }
            }
          }
        },
        "responses": {
          "200": { "description": "Senha redefinida com sucesso" },
          "400": { "description": "Token inválido/expirado ou senha fraca" }
        }
      }
    }
  }
}`

const swaggerUIHTML = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>Go-Auth API - Swagger UI</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body { margin: 0; background: #fafafa; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis]
      });
    };
  </script>
</body>
</html>`

// OpenAPIHandler retorna o JSON da especificação OpenAPI 3.0
func OpenAPIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(openAPISpec))
}

// SwaggerUIHandler serve a interface visual interativa do Swagger UI
func SwaggerUIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(swaggerUIHTML))
}
