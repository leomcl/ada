package sandbox

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
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

const readyPollInterval = time.Second

var terminalReadyReasons = map[string]bool{
	SandboxReasonPodFailed:            true,
	SandboxReasonPodSucceeded:         true,
	SandboxReasonInvalidConfiguration: true,
	SandboxReasonExpired:              true,
}

type Summary struct {
	Name      string
	Namespace string
	Repo      string
	Access    string
	Harness   string
	Ready     string
	Reason    string
	CreatedAt time.Time
}

type Client struct {
	kube    kubernetes.Interface
	dynamic dynamic.Interface
}

func NewClient() (*Client, error) {
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
	return &Client{
		kube:    kubeClient,
		dynamic: dynamicClient,
	}, nil
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

func (c *Client) resolveSigningKey(ctx context.Context, systemNamespace, secretName string) ([]byte, error) {
	secret, err := c.kube.CoreV1().Secrets(systemNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get signing key secret %s/%s: %w", systemNamespace, secretName, err)
	}

	key, err := token.ParseSigningKey(secret.Data[signingKeySecretKey])
	if err != nil {
		return nil, fmt.Errorf("signing key secret %s/%s key %q: %w", systemNamespace, secretName, signingKeySecretKey, err)
	}
	return key, nil
}

func (c *Client) Create(ctx context.Context, cfg Config) (*Sandbox, error) {
	cfg.normalize()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	sandboxName := cfg.SandboxName
	if sandboxName == "" {
		var err error
		sandboxName, err = GenerateName(cfg.Repo)
		if err != nil {
			return nil, err
		}
	}
	secretName := sandboxName + "-token"

	signingKey, err := c.resolveSigningKey(ctx, cfg.SystemNamespace, cfg.SigningKeySecret)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(cfg.TTL.Duration)
	mintedToken, err := token.MintSandboxToken(token.SandboxTokenClaims{
		JTI:       sandboxName,
		Repo:      cfg.Repo,
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
	}, signingKey)
	if err != nil {
		return nil, fmt.Errorf("mint sandbox token: %w", err)
	}

	sandboxObj := buildSandbox(cfg, sandboxName, secretName, expiresAt)
	unstructuredSandbox, err := toUnstructured(sandboxObj)
	if err != nil {
		return nil, err
	}

	// Create the Sandbox first so its UID can own the Secret; the pod waits until the Secret exists.
	createdUnstructured, err := c.dynamic.Resource(SandboxGVR).Namespace(cfg.Namespace).Create(ctx, unstructuredSandbox, metav1.CreateOptions{})
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
				managedByLabel:   managedByValue,
				sandboxNameLabel: sandboxName,
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
	if _, err := c.kube.CoreV1().Secrets(cfg.Namespace).Create(ctx, secretObj, metav1.CreateOptions{}); err != nil {
		_ = c.Delete(context.WithoutCancel(ctx), cfg.Namespace, sandboxName)
		return nil, fmt.Errorf("create token secret %s/%s: %w", cfg.Namespace, secretName, err)
	}

	return createdSandbox, nil
}

func (c *Client) WaitReady(ctx context.Context, namespace, sandboxName string) (*Sandbox, error) {
	var readySandbox *Sandbox
	err := wait.PollUntilContextCancel(ctx, readyPollInterval, true, func(ctx context.Context) (bool, error) {
		sb, err := c.Get(ctx, namespace, sandboxName)
		if err != nil {
			return false, err
		}
		cond := meta.FindStatusCondition(sb.Status.Conditions, string(SandboxConditionReady))
		if cond == nil || (cond.ObservedGeneration != 0 && cond.ObservedGeneration < sb.Generation) {
			return false, nil
		}
		switch cond.Status {
		case metav1.ConditionTrue:
			readySandbox = sb
			return true, nil
		case metav1.ConditionFalse:
			if terminalReadyReasons[cond.Reason] {
				return false, fmt.Errorf("sandbox %s failed (%s): %s", sandboxName, cond.Reason, cond.Message)
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, fmt.Errorf("wait for sandbox %s: %w", sandboxName, err)
	}
	return readySandbox, nil
}

func (c *Client) Get(ctx context.Context, namespace, name string) (*Sandbox, error) {
	u, err := c.dynamic.Resource(SandboxGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get sandbox %s/%s: %w", namespace, name, err)
	}
	return fromUnstructured(u)
}

func (c *Client) List(ctx context.Context, namespace string) ([]Summary, error) {
	list, err := c.dynamic.Resource(SandboxGVR).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: managedByLabel + "=" + managedByValue,
	})
	if err != nil {
		return nil, fmt.Errorf("list sandboxes in %s: %w", namespace, err)
	}

	summaries := make([]Summary, 0, len(list.Items))
	for i := range list.Items {
		sb, err := fromUnstructured(&list.Items[i])
		if err != nil {
			return nil, err
		}
		readyStatus := "Pending"
		readyReason := ""
		if cond := meta.FindStatusCondition(sb.Status.Conditions, string(SandboxConditionReady)); cond != nil {
			readyStatus = string(cond.Status)
			readyReason = cond.Reason
		}
		summaries = append(summaries, Summary{
			Name:      sb.Name,
			Namespace: sb.Namespace,
			Repo:      Repo(sb),
			Access:    sb.Annotations[accessAnnotation],
			Harness:   Harness(sb),
			Ready:     readyStatus,
			Reason:    readyReason,
			CreatedAt: sb.CreationTimestamp.Time,
		})
	}

	slices.SortFunc(summaries, func(a, b Summary) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.Name, b.Name))
	})
	return summaries, nil
}

func (c *Client) Delete(ctx context.Context, namespace, name string) error {
	if err := c.dynamic.Resource(SandboxGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("delete sandbox %s/%s: %w", namespace, name, err)
	}
	return nil
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
