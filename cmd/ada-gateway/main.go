package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/leomcl/ada/internal/gateway"
	"github.com/leomcl/ada/internal/token"
)

func main() {
	signingKey, err := token.ParseSigningKey([]byte(os.Getenv("ADA_SIGNING_KEY")))
	if err != nil {
		log.Fatalf("ADA_SIGNING_KEY: %v", err)
	}

	handler, err := gateway.NewHandler(gateway.Config{
		SigningKey:       signingKey,
		GitHubPAT:        os.Getenv("GITHUB_PAT"),
		GitHubBaseURL:    envOrDefault("GITHUB_BASE_URL", "https://github.com"),
		GitHubAPIBaseURL: envOrDefault("GITHUB_API_BASE_URL", "https://api.github.com"),
		CLIProxyBaseURL:  envOrDefault("CLIPROXY_BASE_URL", "http://127.0.0.1:8317"),
		CLIProxyAPIKey:   os.Getenv("CLIPROXY_API_KEY"),
	})
	if err != nil {
		log.Fatalf("init gateway: %v", err)
	}

	listenAddr := envOrDefault("ADA_LISTEN_ADDR", "127.0.0.1:8080")
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("ada-gateway listening on %s", listenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
