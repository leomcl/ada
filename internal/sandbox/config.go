package sandbox

import (
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	defaultWorkloadNamespace    = "agent-sandbox-workloads"
	defaultSystemNamespace      = "ada-system"
	defaultSigningKeySecretName = "ada-signing-key"
	signingKeySecretKey         = "signing-key"
	defaultBaseImage            = "ada-base:latest"
	defaultGatewayURL           = "http://ada-gateway.ada-system.svc:8080"
	defaultRuntimeClassName     = "gvisor"
	defaultAccessMode           = "tty"
	defaultTokenTTL             = 12 * time.Hour
)

type Config struct {
	Repo             string          `json:"repo"`
	SandboxName      string          `json:"sandboxName,omitempty"`
	Access           string          `json:"access"`
	Harness          string          `json:"harness"`
	Image            string          `json:"image"`
	Namespace        string          `json:"namespace"`
	SystemNamespace  string          `json:"systemNamespace"`
	SigningKeySecret string          `json:"signingKeySecret"`
	GatewayURL       string          `json:"gatewayURL"`
	RuntimeClass     string          `json:"runtimeClass"`
	TTL              metav1.Duration `json:"ttl"`
	TailscaleAuthKey string          `json:"-"`
}

func Defaults() Config {
	return Config{
		Access:           defaultAccessMode,
		Image:            defaultBaseImage,
		Namespace:        defaultWorkloadNamespace,
		SystemNamespace:  defaultSystemNamespace,
		SigningKeySecret: defaultSigningKeySecretName,
		GatewayURL:       defaultGatewayURL,
		RuntimeClass:     defaultRuntimeClassName,
		TTL:              metav1.Duration{Duration: defaultTokenTTL},
	}
}

func (c *Config) normalize() {
	c.Repo = strings.TrimSuffix(strings.TrimSpace(c.Repo), ".git")
	c.GatewayURL = strings.TrimRight(c.GatewayURL, "/")
}

func (c Config) validate() error {
	if !ValidRepo(c.Repo) {
		return fmt.Errorf("invalid repo %q (expected owner/repo)", c.Repo)
	}
	if !validAccessMode(c.Access) {
		return fmt.Errorf("invalid access mode %q (expected rex, tty, or headless)", c.Access)
	}
	if !validHarness(c.Harness) {
		return fmt.Errorf("invalid harness %q (expected opencode, claude, agy, or empty)", c.Harness)
	}
	if c.TTL.Duration <= 0 {
		return fmt.Errorf("invalid ttl %s (must be positive)", c.TTL.Duration)
	}
	return nil
}

func ValidRepo(repo string) bool {
	if strings.ContainsAny(repo, " \t\n\r") {
		return false
	}
	owner, name, ok := strings.Cut(repo, "/")
	return ok && owner != "" && name != "" && !strings.Contains(name, "/")
}

func validAccessMode(access string) bool {
	switch access {
	case "rex", "tty", "headless":
		return true
	default:
		return false
	}
}

func validHarness(harness string) bool {
	switch harness {
	case "", "opencode", "claude", "agy":
		return true
	default:
		return false
	}
}
