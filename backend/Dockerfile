# ==========================================
# ETAPA 1: Build da aplicação (Compilação)
# ==========================================
FROM golang:1.27-alpine AS builder

# Instala certificados CA caso precise fazer requisições HTTPS externas
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copia os arquivos de dependências primeiro (aproveita o cache do Docker)
COPY go.mod ./
RUN touch go.sum
RUN go mod download

# Copia todo o código fonte
COPY . .

# Compila o binário otimizado e estático
# CGO_ENABLED=0 remove dependências de C (gerando um binário 100% puro Go)
# -ldflags="-w -s" remove símbolos de debug para diminuir radicalmente o tamanho
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /main ./cmd/api
# ==========================================
# ETAPA 2: Imagem final de execução (Mínima)
# ==========================================
FROM scratch

# Copia certificados e fuso horário da etapa de build
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copia o binário compilado
COPY --from=builder /main /main

# Expõe a porta que sua API vai rodar (exemplo: 8080)
EXPOSE 8080

# Executa o binário
ENTRYPOINT ["/main"]