package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/jailtonjunior94/keycloak-sso-backend/configs"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt"
)

func main() {
	config, err := configs.LoadConfig(".")
	if err != nil {
		panic(err)
	}

	router := chi.NewRouter()
	router.Use(middleware.Heartbeat("/health"))

	router.Route("/products", func(r chi.Router) {
		r.Use(Authorization(config))
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			u := r.Context().Value(userCtxKey).(*user)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(u)
		})
	})

	server := &http.Server{
		ReadTimeout:       time.Duration(60) * time.Second,
		ReadHeaderTimeout: time.Duration(60) * time.Second,
		Handler:           router,
		Addr:              fmt.Sprintf(":%s", config.HttpServerPort),
	}

	connectionsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		if err := server.Shutdown(context.Background()); err != nil {
			log.Printf("HTTP Server Shutdown Error: %v", err)
		}
		close(connectionsClosed)
	}()

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe Error: %v", err)
	}
	<-connectionsClosed
}

func Authorization(config *configs.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			secretKey := "-----BEGIN CERTIFICATE-----\n" + config.KeycloakPublicKey + "\n-----END CERTIFICATE-----"
			key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(secretKey))
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			tokenReq := tokenFromHeader(r)
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
			ctx := context.WithValue(r.Context(), userCtxKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func tokenFromHeader(r *http.Request) string {
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

var userCtxKey = &contextKey{"user"}

type contextKey struct {
	name string
}

type user struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func NewUser(id, email string) *user {
	return &user{ID: id, Email: email}
}
