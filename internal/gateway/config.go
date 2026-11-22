package gateway

import (
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

const (
	DefaultConfigPath           = "/etc/ada/gateway.yaml"
	DefaultListenAddr           = "127.0.0.1:8080"
	DefaultGitHubBaseURL        = "https://github.com"
	DefaultGitHubAPIBaseURL     = "https://api.github.com"
	DefaultCLIProxyBaseURL      = "http://127.0.0.1:8317"
	DefaultOpenAIUpstreamURL    = "https://api.openai.com"
	DefaultAnthropicUpstreamURL = "https://api.anthropic.com"
	DefaultGoogleUpstreamURL    = "https://generativelanguage.googleapis.com"
)

type Settings struct {
	ListenAddr string           `json:"listenAddr"`
	GitHub     GitHubSettings   `json:"github"`
	CLIProxy   CLIProxySettings `json:"cliproxy"`
	Providers  ProviderSettings `json:"providers"`
}

type GitHubSettings struct {
	BaseURL    string `json:"baseURL"`
	APIBaseURL string `json:"apiBaseURL"`
}

type CLIProxySettings struct {
	Enabled bool   `json:"enabled"`
	BaseURL string `json:"baseURL"`
}

type ProviderSettings struct {
	OpenAI    ProviderEndpoint `json:"openai"`
	Anthropic ProviderEndpoint `json:"anthropic"`
	Google    ProviderEndpoint `json:"google"`
}

type ProviderEndpoint struct {
	UpstreamURL string `json:"upstreamURL"`
}

type Secrets struct {
	SigningKey      []byte
	GitHubPAT       string
	CLIProxyAPIKey  string
	OpenAIAPIKey    string
	AnthropicAPIKey string
	GoogleAPIKey    string
}

func DefaultSettings() Settings {
	return (Settings{}).withDefaults()
}

func LoadSettings(path string) (Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Settings{}, err
	}

	var settings Settings
	if err := yaml.UnmarshalStrict(data, &settings); err != nil {
		return Settings{}, fmt.Errorf("parse gateway config %s: %w", path, err)
	}
	return settings.withDefaults(), nil
}

func (s Settings) withDefaults() Settings {
	s.ListenAddr = stringOrDefault(s.ListenAddr, DefaultListenAddr)
	s.GitHub.BaseURL = stringOrDefault(s.GitHub.BaseURL, DefaultGitHubBaseURL)
	s.GitHub.APIBaseURL = stringOrDefault(s.GitHub.APIBaseURL, DefaultGitHubAPIBaseURL)
	s.CLIProxy.BaseURL = stringOrDefault(s.CLIProxy.BaseURL, DefaultCLIProxyBaseURL)
	s.Providers.OpenAI.UpstreamURL = stringOrDefault(s.Providers.OpenAI.UpstreamURL, DefaultOpenAIUpstreamURL)
	s.Providers.Anthropic.UpstreamURL = stringOrDefault(s.Providers.Anthropic.UpstreamURL, DefaultAnthropicUpstreamURL)
	s.Providers.Google.UpstreamURL = stringOrDefault(s.Providers.Google.UpstreamURL, DefaultGoogleUpstreamURL)
	return s
}

func (s Secrets) trimmed() Secrets {
	s.GitHubPAT = strings.TrimSpace(s.GitHubPAT)
	s.CLIProxyAPIKey = strings.TrimSpace(s.CLIProxyAPIKey)
	s.OpenAIAPIKey = strings.TrimSpace(s.OpenAIAPIKey)
	s.AnthropicAPIKey = strings.TrimSpace(s.AnthropicAPIKey)
	s.GoogleAPIKey = strings.TrimSpace(s.GoogleAPIKey)
	return s
}

func stringOrDefault(raw, fallback string) string {
	if trimmed := strings.TrimSpace(raw); trimmed != "" {
		return trimmed
	}
	return fallback
}
