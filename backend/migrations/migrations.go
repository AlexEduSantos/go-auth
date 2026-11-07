package migrations

import "embed"

// FS embute todos os arquivos de migração SQL diretamente dentro do binário Go compilado.
// Isso garante que imagens Docker minimalistas (como FROM scratch) não precisem copiar pastas externas.
//
//go:embed *.sql
var FS embed.FS
