package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
