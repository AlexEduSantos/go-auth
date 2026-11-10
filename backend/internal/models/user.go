package models

import (
	"time"
)

type UserRole string

const (
	RoleAdmin     UserRole = "ADMIN"
	RolePublisher UserRole = "PUBLISHER"
	RoleManager   UserRole = "MANAGER"
	RoleUser      UserRole = "USER"
)

type User struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	Name       string    `json:"name"`
	Email      string    `json:"email"`
	Password   string    `json:"-"` // O "-" omite a senha ao serializar para JSON
	Role       UserRole  `json:"role"`
	IsVerified bool      `json:"is_verified"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
