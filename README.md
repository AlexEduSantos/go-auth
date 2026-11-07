# Go Auth API 🚀

Uma API de Autenticação e Gestão de Utilizadores de nível corporativo (_Enterprise-grade_), desenvolvida em **Go** utilizando a biblioteca padrão e **Clean Architecture**, acoplada ao **PostgreSQL** e totalmente conteinerizada com **Docker**.

O projeto foi construído priorizando a integridade relacional, resiliência e as melhores práticas de segurança de mercado, evitando "mágicas" de ORMs pesados e utilizando o ecossistema nativo do Go.

---

## 🛠️ Stack Tecnológica

- **Linguagem:** Go (Standard Library, `net/http`)
- **Base de Dados:** PostgreSQL (Driver nativo `pgx/v5` e pool de conexões `pgxpool`)
- **Autenticação:** JWT (`golang-jwt/v5`) com Access Tokens de curta duração (15 min) e Refresh Tokens rotativos (7 dias)
- **Segurança:** Bcrypt, Rate Limiting (`x/time/rate`), Cookies `HttpOnly`, Proteção CSRF (_Double Submit Cookie_) e Security Headers
- **Infraestrutura:** Docker (Multi-stage build `FROM scratch`) & Docker Compose
- **Documentação & Ferramentas:** Swagger UI (OpenAPI 3.0), Migrações SQL embutidas (`embed.FS` / padrão `golang-migrate`) e logs estruturados via `log/slog` (Terminal + PostgreSQL `JSONB`)

---

## 📂 Arquitetura do Projeto

O repositório segue os princípios de **Clean Architecture**, organizado de forma modular e limpa:

```text
backend/
├── cmd/
│   └── api/                  # Ponto de entrada da aplicação (main.go)
├── internal/
│   ├── database/             # Executor automático de migrações SQL (embed.FS)
│   ├── docs/                 # Especificação OpenAPI 3.0 e interface Swagger UI
│   ├── handlers/             # Camada de apresentação (HTTP Handlers + Testes)
│   ├── logger/               # Configuração de logs estruturados (slog -> Stdout + PostgreSQL)
│   ├── middleware/           # Middlewares (Auth, RBAC, Rate Limit, CSRF, Security Headers, Logging)
│   ├── models/               # Entidades e definições de domínio (User, Session, Enums)
│   └── repository/           # Camada de persistência e workers de limpeza no PostgreSQL
├── migrations/               # Migrações versionadas (*.up.sql / *.down.sql) embutidas no binário
└── Dockerfile                # Build multi-estágio otimizado (imagem final FROM scratch)
```

---

## 📍 Rotas da API

### Rotas Públicas

| Método | Endpoint | Descrição |
| :--- | :--- | :--- |
| `GET` | `/api/csrf-token` | Emissão de CSRF Token (`csrf_token` cookie + header `X-CSRF-Token`) |
| `POST` | `/api/register` | Registo de novo utilizador (com validação rigorosa, força de senha e hash bcrypt) |
| `POST` | `/api/login` | Autenticação híbrida (email ou username), emissão de Cookies `HttpOnly` (`auth_token` e `refresh_token`) e `csrf_token` |
| `POST` | `/api/forgot-password` | Solicitação de recuperação de senha (geração de token temporário de 1h) |
| `POST` | `/api/reset-password` | Redefinição de senha utilizando o token válido |
| `GET` | `/swagger` | Documentação interativa da API (OpenAPI 3.0 / Swagger UI) |
| `GET` | `/openapi.json` | Especificação OpenAPI 3.0 em formato JSON |
| `GET` | `/health` | Verificação de saúde da aplicação (_Healthcheck_) |

### Rotas Protegidas (Exigem Cookie + Header `X-CSRF-Token`)

| Método | Endpoint | Restrição / Permissão | Descrição |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/refresh` | Cookie `refresh_token` + CSRF | Renovação do Access Token com **Refresh Token Rotation** |
| `POST` | `/api/logout` | Autenticado (`auth_token`) + CSRF | Encerra a sessão no banco e expira os cookies no navegador |
| `GET` | `/api/profile` | Autenticado (`USER`, `ADMIN`, etc.) | Retorna os dados do perfil do utilizador autenticado |
| `DELETE` | `/api/users` | Restrito (`ADMIN`) | Remove um utilizador do sistema (Protegido por RBAC) |

---

## 🔒 Decisões de Arquitetura e Segurança

Cada escolha técnica implementada neste projeto reflete padrões exigidos em ambientes de produção modernos:

- **Validação Rigorosa e Força de Senha:**
  Validação estrita de formato de e-mail (`net/mail`), username e complexidade de senha (mínimo de 8 caracteres, maiúsculas, minúsculas, números e símbolos) **antes** do processamento de hash `bcrypt`, mantendo o suporte a login híbrido (e-mail ou username).

- **Rate Limiting (Token Bucket):**
  Implementado com `golang.org/x/time/rate`. Protege endpoints críticos de autenticação (`/api/login`, `/api/forgot-password`, etc.) contra ataques de força bruta e abusos baseados no endereço IP do cliente.

- **Cookies `HttpOnly`, `Secure` e `SameSite`:**
  Os tokens de sessão não são expostos no corpo JSON (evitando armazenamento vulnerável no `localStorage`). São transmitidos via cookies com restrição estrita contra acesso via JavaScript, mitigando vetores de ataque **XSS (Cross-Site Scripting)**.

- **Refresh Token Rotation:**
  Separação rigorosa entre o **Access Token** (vida curta de 15 minutos para tráfego diário) e o **Refresh Token** (vida longa de 7 dias, rotativo e vinculado à tabela `session` no PostgreSQL). A cada chamada em `/api/refresh`, o identificador anterior (`sid`) é imediatamente invalidado e substituído por um novo.

- **Proteção contra CSRF (_Double Submit Cookie_):**
  Mitigação de requisições forçadas entre sites (Cross-Site Request Forgery) exigindo que requisições que modificam estado (`POST`, `PUT`, `PATCH`, `DELETE`) enviem o cabeçalho `X-CSRF-Token` idêntico ao cookie `csrf_token`, validado em tempo constante (`crypto/subtle`).

- **Cabeçalhos de Segurança HTTP (_Security Headers_):**
  Injeção automática de headers restritivos em todas as respostas para blindar o navegador contra Clickjacking, MIME-sniffing e ataques de downgrade:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy: default-src 'self'`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`

- **RBAC (_Role-Based Access Control_):**
  Sistema de autorização baseado em cargos tipados (`ADMIN`, `PUBLISHER`, `MANAGER`, `USER`). O middleware unificado valida o JWT, injeta os dados tipados no `context.Context` da requisição e verifica permissões granulares via `RequireRole`.

- **Gestão de Sessões no PostgreSQL:**
  As sessões ativas são persistidas na tabela `session` (com identificador `sid`, payload `JSONB` e data de expiração). Uma rotina em background (*worker* periódico) limpa automaticamente sessões expiradas.

- **Recuperação de Senha Segura:**
  Utiliza tokens criptograficamente seguros gerados via `crypto/rand` com tempo de expiração restrito (1 hora) e invalidação imediata após o uso bem-sucedido.

- **Logs Estruturados (`log/slog`) + Persistência Assíncrona:**
  Emissão de logs em formato JSON tanto no terminal (`Stdout`) quanto na tabela `app_logs` (`JSONB`) do PostgreSQL de forma assíncrona (`io.MultiWriter`), classificando níveis por status HTTP e contando com rotina automática de retenção (limpeza de logs com mais de 30 dias).

- **Migrações de Banco de Dados Embutidas (`embed.FS`):**
  Versionamento estruturado do esquema relacional do PostgreSQL (`000001`, `000002`, etc.) compilado diretamente dentro do binário Go, permitindo execução automática ao iniciar o container `FROM scratch`.

- **Testes Automatizados:**
  Suíte de testes unitários e de handlers HTTP (`httptest`) validando regras de entrada, força de senha, controle de acesso (RBAC), headers de segurança e proteção CSRF.

---

## ▶️ Como Executar o Projeto

### 1. Clone o repositório

```bash
git clone https://github.com/AlexEduSantos/go-auth.git
cd go-auth
```

### 2. Suba o ambiente completo com Docker Compose

```bash
docker compose up --build -d
```

### 3. Executar os testes automatizados localmente

```bash
go test -C backend -v ./...
```

### 4. Aceda à API

- **API Base URL:** `http://localhost:8080`
- **Documentação Interativa (Swagger UI):** `http://localhost:8080/swagger`
- **Especificação OpenAPI 3.0 (JSON):** `http://localhost:8080/openapi.json`
