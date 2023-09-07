package middlewares

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/jailtonjunior94/keycloak-sso-backend/configs"
)

type Authorization interface {
	Authorization() func(http.Handler) http.Handler
}

type authorization struct {
	config *configs.Config
}

func NewAuthorization(config *configs.Config) Authorization {
	return &authorization{config: config}
}

func (a *authorization) Authorization() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			secretKey := "-----BEGIN CERTIFICATE-----\n" + a.config.KeycloakPublicKey + "\n-----END CERTIFICATE-----"
			key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(secretKey))
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			tokenReq := a.tokenFromHeader(r)
			if tokenReq == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			token, err := jwt.Parse(tokenReq, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, errors.New("token inválido")
				}
				return key, nil
			})

			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if !token.Valid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			user := NewUser(claims["sub"].(string), claims["email"].(string))
			ctx := context.WithValue(r.Context(), UserCtxKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (a *authorization) tokenFromHeader(r *http.Request) string {
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

var UserCtxKey = &contextKey{"user"}

type contextKey struct {
	name string
}

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func NewUser(id, email string) *User {
	return &User{ID: id, Email: email}
}
