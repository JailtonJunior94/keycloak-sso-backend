package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jailtonjunior94/keycloak-sso-backend/pkg/bundle"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	container := bundle.NewContainer()

	router := chi.NewRouter()
	router.Use(middleware.Heartbeat("/health"))

	router.Route("/products", func(r chi.Router) {
		r.Use(container.Authorization.Authorization())
		r.Get("/", container.ProductHandler.Products)
	})

	server := &http.Server{
		ReadTimeout:       time.Duration(60) * time.Second,
		ReadHeaderTimeout: time.Duration(60) * time.Second,
		Handler:           router,
		Addr:              fmt.Sprintf(":%s", container.Config.HttpServerPort),
	}

	idleConnectionsClosed := make(chan struct{})
	go gracefulShutdown(server, idleConnectionsClosed)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe Error: %v", err)
	}
	log.Printf("🚀 API is running")
	<-idleConnectionsClosed
}

func gracefulShutdown(server *http.Server, idleConnectionsClosed chan struct{}) {
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	signal.Notify(sigint, syscall.SIGTERM)
	<-sigint

	log.Println("service interrupt received")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("HTTP Server Shutdown Error: %v", err)
	}

	log.Println("shutdown complete")
	close(idleConnectionsClosed)
}
