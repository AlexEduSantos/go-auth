# Go Auth API 🚀

Uma API de Autenticação e Gestão de Utilizadores de nível corporativo (*Enterprise-grade*), desenvolvida em **Go** utilizando a biblioteca padrão e Clean Architecture, acoplada ao **PostgreSQL** e totalmente conteinerizada com **Docker**.

O projeto foi construído priorizando a integridade relacional, resiliência e as melhores práticas de segurança de mercado, evitando "mágicas" de ORMs pesados e utilizando o ecossistema nativo do Go.

---

## 🛠️ Stack Tecnológica

* **Linguagem:** Go (Standard Library, `net/http`)
* **Base de Dados:** PostgreSQL (Driver nativo `pgx/v5` e pool de conexões `pgxpool`)
* **Autenticação:** JWT (`golang-jwt/v5`) com Access Tokens de curta duração e Refresh Tokens rotativos
* **Segurança:** Bcrypt, Rate Limiting (`x/time/rate`), Cookies `HttpOnly`, Proteção CSRF e Security Headers
* **Infraestrutura:** Docker & Docker Compose
* **Documentação & Ferramentas:** Swagger (OpenAPI), `golang-migrate` e logs estruturados via `log/slog`

---

## 📂 Arquitetura do Projeto

O repositório segue os princípios de **Clean Architecture**, organizado num monorepo limpo:

```text
.
├── cmd/
│   └── api/                  # Ponto de entrada da aplicação (main.go)
├── internal/
│   ├── handlers/             # Camada de apresentação (HTTP Handlers / Controllers)
│   ├── logger/               # Configuração de logs estruturados
│   ├── middleware/           # Middlewares (Auth, RBAC, Rate Limit, CSRF, Security Headers, Logging)
│   ├── models/               # Entidades e definições de domínio (User, Session, Enums)
│   └── repository/           # Camada de persistência e interação com o PostgreSQL
├── db/
│   └── migrations/           # Migrações versionadas do banco de dados (golang-migrate)
├── docker-compose.yml        # Orquestração de containers (API + PostgreSQL)
└── Dockerfile                # Build multi-estágio otimizado para Go