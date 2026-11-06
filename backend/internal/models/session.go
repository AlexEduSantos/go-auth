package models

import (
	"time"
)

type Session struct {
	SID    string    `json:"sid"`
	Sess   []byte    `json:"sess"` // Armazena os dados da sessão serializados em JSON
	Expire time.Time `json:"expire"`
}
