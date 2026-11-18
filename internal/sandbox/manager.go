package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/leomcl/ada/internal/token"
)

const (
	DefaultWorkloadNamespace    = "agent-sandbox-workloads"
	DefaultSystemNamespace      = "ada-system"
	DefaultSigningKeySecretName = "ada-signing-key"
	DefaultSigningKeySecretKey  = "signing-key"
	DefaultBaseImage            = "ada-base:latest"
	DefaultGatewayURL           = "http://ada-gateway.ada-system.svc:8080"
	DefaultRuntimeClassName     = "gvisor"
	DefaultAccessMode           = "tty"
	DefaultTokenTTL             = 12 * time.Hour

	ManagedByLabel    = "app.kubernetes.io/managed-by"
	ManagedByValue    = "ada"
	SandboxNameLabel  = "ada.io/sandbox"
	RepoAnnotation    = "ada.io/repo"
	AccessAnnotation  = "ada.io/access"
	HarnessAnnotation = "ada.io/harness"
	PodNameAnnotation = "agents.x-k8s.io/pod-name"
)

var terminalReadyReasons = map[string]bool{
	SandboxReasonPodFailed:            true,
	SandboxReasonPodSucceeded:         true,
	SandboxReasonInvalidConfiguration: true,
	SandboxReasonExpired:              true,
}

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
		Access:           DefaultAccessMode,
		Image:            DefaultBaseImage,
		Namespace:        DefaultWorkloadNamespace,
		SystemNamespace:  DefaultSystemNamespace,
		SigningKeySecret: DefaultSigningKeySecretName,
		GatewayURL:       DefaultGatewayURL,
		RuntimeClass:     DefaultRuntimeClassName,
		TTL:              metav1.Duration{Duration: DefaultTokenTTL},
	}
}

type SandboxSummary struct {
	Name      string
	Namespace string
	Repo      string
	Access    string
	Harness   string
	Ready     string
	Reason    string
	CreatedAt time.Time
}

type Manager struct {
	kube    kubernetes.Interface
	dynamic dynamic.Interface
	now     func() time.Time
}

func NewManager(kube kubernetes.Interface, dynamicClient dynamic.Interface, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{
		kube:    kube,
		dynamic: dynamicClient,
		now:     now,
	}
}

func NewClusterManager() (*Manager, error) {
	cfg, err := loadKubeConfig()
	if err != nil {
		return nil, err
	}
	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}
	return NewManager(kubeClient, dynamicClient, nil), nil
}

func loadKubeConfig() (*rest.Config, error) {
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err == nil {
		return cfg, nil
	}
	inClusterCfg, inClusterErr := rest.InClusterConfig()
	if inClusterErr == nil {
		return inClusterCfg, nil
	}
	return nil, fmt.Errorf("load kubeconfig: %w", err)
}

func (m *Manager) resolveSigningKey(ctx context.Context, systemNamespace, secretName string) ([]byte, error) {
	secret, err := m.kube.CoreV1().Secrets(systemNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get signing key secret %s/%s: %w", systemNamespace, secretName, err)
	}

	key, err := token.ParseSigningKey(secret.Data[DefaultSigningKeySecretKey])
	if err != nil {
		return nil, fmt.Errorf("signing key secret %s/%s key %q: %w", systemNamespace, secretName, DefaultSigningKeySecretKey, err)
	}
	return key, nil
}

func (m *Manager) Create(ctx context.Context, cfg Config) (*Sandbox, error) {
	cfg.Repo = strings.TrimSuffix(strings.TrimSpace(cfg.Repo), ".git")
	cfg.GatewayURL = strings.TrimRight(cfg.GatewayURL, "/")

	if !ValidRepo(cfg.Repo) {
		return nil, fmt.Errorf("invalid repo %q (expected owner/repo)", cfg.Repo)
	}
	if !ValidAccessMode(cfg.Access) {
		return nil, fmt.Errorf("invalid access mode %q (expected rex, tty, or headless)", cfg.Access)
	}
	if !ValidHarness(cfg.Harness) {
		return nil, fmt.Errorf("invalid harness %q (expected opencode, claude, agy, or empty)", cfg.Harness)
	}
	if cfg.TTL.Duration <= 0 {
		return nil, fmt.Errorf("invalid ttl %s (must be positive)", cfg.TTL.Duration)
	}

	sandboxName := cfg.SandboxName
	if sandboxName == "" {
		var err error
		sandboxName, err = GenerateSandboxName(cfg.Repo)
		if err != nil {
			return nil, err
		}
	}
	secretName := sandboxName + "-token"

	signingKey, err := m.resolveSigningKey(ctx, cfg.SystemNamespace, cfg.SigningKeySecret)
	if err != nil {
		return nil, err
	}

	now := m.now().UTC()
	mintedToken, err := token.MintSandboxToken(token.SandboxTokenClaims{
		JTI:       sandboxName,
		Repo:      cfg.Repo,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(cfg.TTL.Duration).Unix(),
	}, signingKey)
	if err != nil {
		return nil, fmt.Errorf("mint sandbox token: %w", err)
	}

	sandboxObj := buildSandboxManifest(cfg, sandboxName, secretName, now)
	unstructuredSandbox, err := toUnstructured(sandboxObj)
	if err != nil {
		return nil, err
	}

	createdUnstructured, err := m.dynamic.Resource(SandboxGVR).Namespace(cfg.Namespace).Create(ctx, unstructuredSandbox, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create sandbox %s/%s: %w", cfg.Namespace, sandboxName, err)
	}

	createdSandbox, err := fromUnstructured(createdUnstructured)
	if err != nil {
		return nil, err
	}

	secretData := map[string][]byte{
		"token": []byte(mintedToken),
	}
	if cfg.TailscaleAuthKey != "" {
		secretData["ts-authkey"] = []byte(cfg.TailscaleAuthKey)
	}

	secretObj := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cfg.Namespace,
			Labels: map[string]string{
				ManagedByLabel:   ManagedByValue,
				SandboxNameLabel: sandboxName,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: SandboxGroupVersion.String(),
					Kind:       SandboxKind,
					Name:       createdSandbox.Name,
					UID:        createdSandbox.UID,
				},
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}
	if _, err := m.kube.CoreV1().Secrets(cfg.Namespace).Create(ctx, secretObj, metav1.CreateOptions{}); err != nil {
		_ = m.Delete(context.WithoutCancel(ctx), cfg.Namespace, sandboxName)
		return nil, fmt.Errorf("create token secret %s/%s: %w", cfg.Namespace, secretName, err)
	}

	return createdSandbox, nil
}

func (m *Manager) WaitUntilReady(ctx context.Context, namespace, sandboxName string, pollInterval time.Duration) (*Sandbox, error) {
	if pollInterval <= 0 {
		pollInterval = time.Second
	}

	var readySandbox *Sandbox
	err := wait.PollUntilContextCancel(ctx, pollInterval, true, func(ctx context.Context) (bool, error) {
		sb, err := m.Get(ctx, namespace, sandboxName)
		if err != nil {
			return false, err
		}
		if readyCond := findCondition(sb.Status.Conditions, string(SandboxConditionReady)); readyCond != nil {
			if readyCond.ObservedGeneration == 0 || readyCond.ObservedGeneration >= sb.Generation {
				if readyCond.Status == metav1.ConditionTrue {
					readySandbox = sb
					return true, nil
				}
				if readyCond.Status == metav1.ConditionFalse && terminalReadyReasons[readyCond.Reason] {
					return false, fmt.Errorf("sandbox %s failed (%s): %s", sandboxName, readyCond.Reason, readyCond.Message)
				}
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, fmt.Errorf("wait for sandbox %s: %w", sandboxName, err)
	}
	return readySandbox, nil
}

func (m *Manager) Get(ctx context.Context, namespace, name string) (*Sandbox, error) {
	u, err := m.dynamic.Resource(SandboxGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get sandbox %s/%s: %w", namespace, name, err)
	}
	return fromUnstructured(u)
}

func (m *Manager) List(ctx context.Context, namespace string) ([]SandboxSummary, error) {
	list, err := m.dynamic.Resource(SandboxGVR).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: ManagedByLabel + "=" + ManagedByValue,
	})
	if err != nil {
		return nil, fmt.Errorf("list sandboxes in %s: %w", namespace, err)
	}

	summaries := make([]SandboxSummary, 0, len(list.Items))
	for i := range list.Items {
		sb, err := fromUnstructured(&list.Items[i])
		if err != nil {
			return nil, err
		}
		readyStatus := "Pending"
		readyReason := ""
		if cond := findCondition(sb.Status.Conditions, string(SandboxConditionReady)); cond != nil {
			readyStatus = string(cond.Status)
			readyReason = cond.Reason
		}
		summaries = append(summaries, SandboxSummary{
			Name:      sb.Name,
			Namespace: sb.Namespace,
			Repo:      sb.Annotations[RepoAnnotation],
			Access:    sb.Annotations[AccessAnnotation],
			Harness:   sb.Annotations[HarnessAnnotation],
			Ready:     readyStatus,
			Reason:    readyReason,
			CreatedAt: sb.CreationTimestamp.Time,
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		if !summaries[i].CreatedAt.Equal(summaries[j].CreatedAt) {
			return summaries[i].CreatedAt.Before(summaries[j].CreatedAt)
		}
		return summaries[i].Name < summaries[j].Name
	})
	return summaries, nil
}

func (m *Manager) Delete(ctx context.Context, namespace, name string) error {
	if err := m.dynamic.Resource(SandboxGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("delete sandbox %s/%s: %w", namespace, name, err)
	}
	return nil
}

func PodName(sb *Sandbox) string {
	if name := sb.Annotations[PodNameAnnotation]; name != "" {
		return name
	}
	return sb.Name
}

func ValidRepo(repo string) bool {
	if strings.ContainsAny(repo, " \t\n\r") {
		return false
	}
	owner, name, ok := strings.Cut(repo, "/")
	return ok && owner != "" && name != "" && !strings.Contains(name, "/")
}

func ValidAccessMode(access string) bool {
	switch access {
	case "rex", "tty", "headless":
		return true
	default:
		return false
	}
}

func ValidHarness(harness string) bool {
	switch harness {
	case "", "opencode", "claude", "agy":
		return true
	default:
		return false
	}
}

func GenerateSandboxName(prefixSource string) (string, error) {
	name := prefixSource
	if _, repoPart, ok := strings.Cut(prefixSource, "/"); ok {
		name = repoPart
	}
	name = strings.TrimSuffix(name, ".git")
	prefix := sanitizeDNSLabelPrefix(name)
	if prefix == "" {
		prefix = "sandbox"
	} else if prefix[0] < 'a' || prefix[0] > 'z' {
		prefix = "s-" + prefix
	}
	if len(prefix) > 54 {
		prefix = strings.TrimRight(prefix[:54], "-")
		if prefix == "" {
			prefix = "sandbox"
		}
	}

	suffixBytes := make([]byte, 4)
	if _, err := rand.Read(suffixBytes); err != nil {
		return "", fmt.Errorf("generate sandbox suffix: %w", err)
	}
	return prefix + "-" + hex.EncodeToString(suffixBytes), nil
}

func sanitizeDNSLabelPrefix(raw string) string {
	var b strings.Builder
	lastDash := true
	for _, r := range strings.ToLower(raw) {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAlnum {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func buildSandboxManifest(cfg Config, sandboxName, secretName string, now time.Time) *Sandbox {
	labels := map[string]string{
		ManagedByLabel:   ManagedByValue,
		SandboxNameLabel: sandboxName,
	}
	annotations := map[string]string{
		RepoAnnotation:   cfg.Repo,
		AccessAnnotation: cfg.Access,
	}
	if cfg.Harness != "" {
		annotations[HarnessAnnotation] = cfg.Harness
	}

	shutdownTime := metav1.NewTime(now.Add(cfg.TTL.Duration))
	shutdownPolicy := ShutdownPolicyDelete

	podSpec := corev1.PodSpec{
		AutomountServiceAccountToken: boolPtr(false),
		RestartPolicy:                corev1.RestartPolicyNever,
		Containers: []corev1.Container{
			{
				Name:       "sandbox",
				Image:      cfg.Image,
				WorkingDir: "/workspace",
				Env:        buildContainerEnv(cfg, sandboxName, secretName),
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						Exec: &corev1.ExecAction{
							Command: []string{"test", "-f", "/tmp/ada-ready"},
						},
					},
					PeriodSeconds: 1,
				},
			},
		},
	}
	if cfg.RuntimeClass != "" {
		runtimeClass := cfg.RuntimeClass
		podSpec.RuntimeClassName = &runtimeClass
	}

	return &Sandbox{
		TypeMeta: metav1.TypeMeta{
			APIVersion: SandboxGroupVersion.String(),
			Kind:       SandboxKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        sandboxName,
			Namespace:   cfg.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: SandboxSpec{
			SandboxBlueprint: SandboxBlueprint{
				PodTemplate: PodTemplate{
					ObjectMeta: PodMetadata{
						Labels: map[string]string{
							ManagedByLabel:   ManagedByValue,
							SandboxNameLabel: sandboxName,
						},
					},
					Spec: podSpec,
				},
			},
			Lifecycle: Lifecycle{
				ShutdownTime:   &shutdownTime,
				ShutdownPolicy: &shutdownPolicy,
			},
			OperatingMode: SandboxOperatingModeRunning,
		},
	}
}

func buildContainerEnv(cfg Config, sandboxName, secretName string) []corev1.EnvVar {
	secretEnv := func(envName, key string) corev1.EnvVar {
		return corev1.EnvVar{
			Name: envName,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
					Key:                  key,
				},
			},
		}
	}

	env := []corev1.EnvVar{
		secretEnv("ADA_TOKEN", "token"),
		secretEnv("OPENAI_API_KEY", "token"),
		secretEnv("ANTHROPIC_AUTH_TOKEN", "token"),
		secretEnv("GEMINI_API_KEY", "token"),
	}
	if cfg.TailscaleAuthKey != "" {
		env = append(env, secretEnv("TS_AUTHKEY", "ts-authkey"))
	}

	env = append(env,
		corev1.EnvVar{Name: "ADA_REPO", Value: cfg.Repo},
		corev1.EnvVar{Name: "ADA_SANDBOX_NAME", Value: sandboxName},
		corev1.EnvVar{Name: "ACCESS", Value: cfg.Access},
	)
	if cfg.Harness != "" {
		env = append(env, corev1.EnvVar{Name: "HARNESS", Value: cfg.Harness})
	}
	env = append(env,
		corev1.EnvVar{Name: "ADA_GATEWAY", Value: cfg.GatewayURL},
		corev1.EnvVar{Name: "OPENAI_BASE_URL", Value: cfg.GatewayURL + "/v1"},
		corev1.EnvVar{Name: "ANTHROPIC_BASE_URL", Value: cfg.GatewayURL + "/anthropic"},
		corev1.EnvVar{Name: "GEMINI_API_BASE_URL", Value: cfg.GatewayURL + "/google"},
		corev1.EnvVar{Name: "GOOGLE_GEMINI_BASE_URL", Value: cfg.GatewayURL + "/google"},
	)
	return env
}

func toUnstructured(sb *Sandbox) (*unstructured.Unstructured, error) {
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(sb)
	if err != nil {
		return nil, fmt.Errorf("convert sandbox to unstructured: %w", err)
	}
	return &unstructured.Unstructured{Object: obj}, nil
}

func fromUnstructured(u *unstructured.Unstructured) (*Sandbox, error) {
	var sb Sandbox
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &sb); err != nil {
		return nil, fmt.Errorf("convert unstructured to sandbox: %w", err)
	}
	return &sb, nil
}

func findCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

func boolPtr(v bool) *bool {
	return &v
}
