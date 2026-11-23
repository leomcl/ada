package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

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

	restCfg, err := loadKubeConfig()
	if err != nil {
		log.Fatalf("load kubernetes config: %v", err)
	}
	kubeClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Fatalf("create kubernetes client: %v", err)
	}
	dynamicClient, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		log.Fatalf("create dynamic kubernetes client: %v", err)
	}

	controller, err := gateway.NewSandboxController(gateway.SandboxControllerConfig{
		Namespace:  settings.WorkloadsNamespace,
		SigningKey: signingKey,
		Kube:       kubeClient,
		Dynamic:    dynamicClient,
	})
	if err != nil {
		log.Fatalf("init sandbox controller: %v", err)
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
		Sandboxes:   controller,
	})
	if err != nil {
		log.Fatalf("init gateway: %v", err)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctrlCtx, cancelController := context.WithCancel(context.Background())
	controllerDone := make(chan struct{})
	go func() {
		defer close(controllerDone)
		controller.Run(ctrlCtx)
	}()

	server := &http.Server{
		Addr:              settings.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("ada-gateway listening on %s (workloadsNamespace=%s)", settings.ListenAddr, settings.WorkloadsNamespace)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		cancelController()
		<-controllerDone
		if err != nil {
			log.Fatal(err)
		}
	case <-sigCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("http server shutdown: %v", err)
		}
		cancelController()
		<-controllerDone
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

func loadKubeConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	kubeCfg, kubeErr := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if kubeErr == nil {
		return kubeCfg, nil
	}
	return nil, fmt.Errorf("in-cluster (%v) and kubeconfig (%w)", err, kubeErr)
}
