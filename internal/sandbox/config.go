package sandbox

import (
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	DefaultWorkloadsNamespace = "agent-sandbox-workloads"
	DefaultTokenTTL           = 12 * time.Hour

	defaultBaseImage        = "ada-base:latest"
	defaultGatewayURL       = "http://ada-gateway.ada-system.svc:8080"
	defaultRuntimeClassName = "gvisor"
	defaultAccessMode       = "tty"
	defaultCPU              = "2"
	defaultMemory           = "4Gi"
	defaultEphemeralStorage = "10Gi"
)

type Config struct {
	Repo             string          `json:"repo"`
	SandboxName      string          `json:"sandboxName,omitempty"`
	Access           string          `json:"access"`
	Harness          string          `json:"harness"`
	Image            string          `json:"image"`
	Namespace        string          `json:"namespace"`
	GatewayURL       string          `json:"gatewayURL"`
	RuntimeClass     string          `json:"runtimeClass"`
	CPU              string          `json:"cpu"`
	Memory           string          `json:"memory"`
	EphemeralStorage string          `json:"ephemeralStorage"`
	Spot             bool            `json:"spot,omitempty"`
	TTL              metav1.Duration `json:"ttl"`
	TailscaleAuthKey string          `json:"-"`
}

func Defaults() Config {
	return Config{
		Access:           defaultAccessMode,
		Image:            defaultBaseImage,
		Namespace:        DefaultWorkloadsNamespace,
		GatewayURL:       defaultGatewayURL,
		RuntimeClass:     defaultRuntimeClassName,
		CPU:              defaultCPU,
		Memory:           defaultMemory,
		EphemeralStorage: defaultEphemeralStorage,
		TTL:              metav1.Duration{Duration: DefaultTokenTTL},
	}
}

func (c *Config) normalize() {
	c.Repo = strings.TrimSuffix(strings.TrimSpace(c.Repo), ".git")
	c.GatewayURL = strings.TrimRight(c.GatewayURL, "/")
	c.CPU = strings.TrimSpace(c.CPU)
	c.Memory = strings.TrimSpace(c.Memory)
	c.EphemeralStorage = strings.TrimSpace(c.EphemeralStorage)
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
	if err := validateQuantity("cpu", c.CPU); err != nil {
		return err
	}
	if err := validateQuantity("memory", c.Memory); err != nil {
		return err
	}
	if err := validateQuantity("ephemeral-storage", c.EphemeralStorage); err != nil {
		return err
	}
	if c.TTL.Duration <= 0 {
		return fmt.Errorf("invalid ttl %s (must be positive)", c.TTL.Duration)
	}
	return nil
}

func validateQuantity(name, raw string) error {
	if raw == "" {
		return nil
	}
	q, err := resource.ParseQuantity(raw)
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", name, raw, err)
	}
	if q.Sign() <= 0 {
		return fmt.Errorf("invalid %s %q (must be positive)", name, raw)
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
