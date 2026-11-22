package main

import (
	"errors"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/leomcl/ada/internal/gateway"
	"github.com/leomcl/ada/internal/token"
)

func main() {
	configPath := flag.String("config", "", "path to gateway.yaml config file (default "+gateway.DefaultConfigPath+")")
	flag.Parse()

	settings, err := loadSettings(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	signingKey, err := token.ParseSigningKey([]byte(os.Getenv("ADA_SIGNING_KEY")))
	if err != nil {
		log.Fatalf("ADA_SIGNING_KEY: %v", err)
	}

	handler, err := gateway.NewHandler(gateway.Config{
		Settings: settings,
		Secrets: gateway.Secrets{
			SigningKey:      signingKey,
			GitHubPAT:       os.Getenv("GITHUB_PAT"),
			CLIProxyAPIKey:  os.Getenv("CLIPROXY_API_KEY"),
			OpenAIAPIKey:    os.Getenv("OPENAI_API_KEY"),
			AnthropicAPIKey: os.Getenv("ANTHROPIC_API_KEY"),
			GoogleAPIKey:    os.Getenv("GEMINI_API_KEY"),
		},
		AuditLogger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	})
	if err != nil {
		log.Fatalf("init gateway: %v", err)
	}

	server := &http.Server{
		Addr:              settings.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("ada-gateway listening on %s", settings.ListenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func loadSettings(path string) (gateway.Settings, error) {
	if path != "" {
		return gateway.LoadSettings(path)
	}
	settings, err := gateway.LoadSettings(gateway.DefaultConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return gateway.DefaultSettings(), nil
	}
	return settings, err
}
