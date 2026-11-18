package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const (
	managedByLabel    = "app.kubernetes.io/managed-by"
	managedByValue    = "ada"
	sandboxNameLabel  = "ada.io/sandbox"
	repoAnnotation    = "ada.io/repo"
	accessAnnotation  = "ada.io/access"
	harnessAnnotation = "ada.io/harness"
	podNameAnnotation = "agents.x-k8s.io/pod-name"
)

func PodName(sb *Sandbox) string {
	if name := sb.Annotations[podNameAnnotation]; name != "" {
		return name
	}
	return sb.Name
}

func Repo(sb *Sandbox) string {
	return sb.Annotations[repoAnnotation]
}

func Harness(sb *Sandbox) string {
	return sb.Annotations[harnessAnnotation]
}

func GenerateName(repo string) (string, error) {
	if _, name, ok := strings.Cut(repo, "/"); ok {
		repo = name
	}
	prefix := sanitizeDNSLabel(strings.TrimSuffix(repo, ".git"))
	if prefix == "" {
		prefix = "s"
	} else if prefix[0] < 'a' || prefix[0] > 'z' {
		prefix = "s-" + prefix
	}
	if len(prefix) > 54 {
		prefix = strings.TrimRight(prefix[:54], "-")
	}
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generate sandbox suffix: %w", err)
	}
	return prefix + "-" + hex.EncodeToString(suffix[:]), nil
}

func sanitizeDNSLabel(raw string) string {
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

func buildSandbox(cfg Config, sandboxName, secretName string, expiresAt time.Time) *Sandbox {
	labels := map[string]string{
		managedByLabel:   managedByValue,
		sandboxNameLabel: sandboxName,
	}
	annotations := map[string]string{
		repoAnnotation:   cfg.Repo,
		accessAnnotation: cfg.Access,
	}
	if cfg.Harness != "" {
		annotations[harnessAnnotation] = cfg.Harness
	}

	podSpec := corev1.PodSpec{
		AutomountServiceAccountToken: ptr.To(false),
		RestartPolicy:                corev1.RestartPolicyNever,
		Containers: []corev1.Container{
			{
				Name:       "sandbox",
				Image:      cfg.Image,
				WorkingDir: "/workspace",
				Env:        buildEnv(cfg, sandboxName, secretName),
				// entrypoint.sh touches /tmp/ada-ready once harness setup and git clone finish.
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
		podSpec.RuntimeClassName = ptr.To(cfg.RuntimeClass)
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
							managedByLabel:   managedByValue,
							sandboxNameLabel: sandboxName,
						},
					},
					Spec: podSpec,
				},
			},
			Lifecycle: Lifecycle{
				ShutdownTime:   ptr.To(metav1.NewTime(expiresAt)),
				ShutdownPolicy: ptr.To(ShutdownPolicyDelete),
			},
			OperatingMode: SandboxOperatingModeRunning,
		},
	}
}

func buildEnv(cfg Config, sandboxName, secretName string) []corev1.EnvVar {
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
