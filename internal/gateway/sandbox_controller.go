package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/leomcl/ada/internal/sandbox"
	"github.com/leomcl/ada/internal/token"
)

type SandboxStore interface {
	HasSynced() bool
	IsActive(name, repo string) bool
	Delete(ctx context.Context, name string) error
}

type SandboxControllerConfig struct {
	Namespace  string
	SigningKey []byte
	Kube       kubernetes.Interface
	Dynamic    dynamic.Interface
	Now        func() time.Time
}

type SandboxController struct {
	namespace  string
	signingKey []byte
	kube       kubernetes.Interface
	dynamic    dynamic.Interface
	informer   cache.SharedIndexInformer
	queue      workqueue.TypedRateLimitingInterface[string]
	now        func() time.Time
}

func NewSandboxController(cfg SandboxControllerConfig) (*SandboxController, error) {
	signingKey, err := token.ParseSigningKey(cfg.SigningKey)
	if err != nil {
		return nil, err
	}
	if cfg.Kube == nil {
		return nil, errors.New("kubernetes client is required")
	}
	if cfg.Dynamic == nil {
		return nil, errors.New("dynamic kubernetes client is required")
	}

	namespace := stringOrDefault(cfg.Namespace, DefaultWorkloadsNamespace)
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	genericInformer := dynamicinformer.NewFilteredDynamicInformer(
		cfg.Dynamic,
		sandbox.SandboxGVR,
		namespace,
		0,
		cache.Indexers{},
		func(opts *metav1.ListOptions) {
			opts.LabelSelector = sandbox.ManagedBySelector
		},
	)

	c := &SandboxController{
		namespace:  namespace,
		signingKey: bytes.Clone(signingKey),
		kube:       cfg.Kube,
		dynamic:    cfg.Dynamic,
		informer:   genericInformer.Informer(),
		queue:      workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		now:        nowFn,
	}

	if _, err := c.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if u, ok := obj.(*unstructured.Unstructured); ok {
				c.queue.Add(u.GetName())
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			oldU, okOld := oldObj.(*unstructured.Unstructured)
			newU, okNew := newObj.(*unstructured.Unstructured)
			if !okOld || !okNew {
				return
			}
			if !isOperatingModeRunning(oldU) && isOperatingModeRunning(newU) {
				c.queue.Add(newU.GetName())
			}
		},
	}); err != nil {
		return nil, fmt.Errorf("register sandbox informer handler: %w", err)
	}

	return c, nil
}

func (c *SandboxController) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.informer.Run(ctx.Done())
	}()

	if cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runWorker(ctx)
		}()
	}

	<-ctx.Done()
	c.queue.ShutDown()
	wg.Wait()
}

func (c *SandboxController) HasSynced() bool {
	return c.informer.HasSynced()
}

func (c *SandboxController) IsActive(name, repo string) bool {
	if name == "" || !sandbox.ValidRepo(repo) {
		return false
	}
	u, ok := c.getCachedUnstructured(name)
	if !ok {
		return false
	}
	return u.GetDeletionTimestamp() == nil &&
		isOperatingModeRunning(u) &&
		u.GetAnnotations()[sandbox.RepoAnnotation] == repo
}

func (c *SandboxController) Delete(ctx context.Context, name string) error {
	return c.dynamic.Resource(sandbox.SandboxGVR).Namespace(c.namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

func (c *SandboxController) getCachedUnstructured(name string) (*unstructured.Unstructured, bool) {
	item, exists, err := c.informer.GetIndexer().GetByKey(c.namespace + "/" + name)
	if err != nil || !exists {
		return nil, false
	}
	u, ok := item.(*unstructured.Unstructured)
	return u, ok
}

func isOperatingModeRunning(u *unstructured.Unstructured) bool {
	mode, found, err := unstructured.NestedString(u.Object, "spec", "operatingMode")
	return err == nil && found && mode == string(sandbox.SandboxOperatingModeRunning)
}

func (c *SandboxController) runWorker(ctx context.Context) {
	for c.processNextItem(ctx) {
	}
}

func (c *SandboxController) processNextItem(ctx context.Context) bool {
	name, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(name)

	if err := c.reconcileTokenSecret(ctx, name); err != nil {
		if ctx.Err() != nil {
			return false
		}
		log.Printf("reconcile token secret for sandbox %s: %v", name, err)
		c.queue.AddRateLimited(name)
		return true
	}
	c.queue.Forget(name)
	return true
}

func (c *SandboxController) reconcileTokenSecret(ctx context.Context, name string) error {
	u, ok := c.getCachedUnstructured(name)
	if !ok || u.GetDeletionTimestamp() != nil || !isOperatingModeRunning(u) {
		return nil
	}

	sb, err := sandbox.FromUnstructured(u)
	if err != nil {
		return fmt.Errorf("decode sandbox %s: %w", name, err)
	}

	repo := sandbox.Repo(sb)
	if !sandbox.ValidRepo(repo) {
		log.Printf("skip token mint for sandbox %s: invalid repo annotation %q", sb.Name, repo)
		return nil
	}

	now := c.now().UTC()
	expiresAt := now.Add(sandbox.DefaultTokenTTL)
	if sb.Spec.Lifecycle.ShutdownTime != nil && !sb.Spec.Lifecycle.ShutdownTime.IsZero() {
		expiresAt = sb.Spec.Lifecycle.ShutdownTime.Time.UTC()
	}
	if !expiresAt.After(now) {
		return nil
	}

	mintedToken, err := token.MintSandboxToken(token.SandboxTokenClaims{
		JTI:       sb.Name,
		Repo:      repo,
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
	}, c.signingKey)
	if err != nil {
		return fmt.Errorf("mint sandbox token: %w", err)
	}

	secretObj := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sandbox.TokenSecretName(sb.Name),
			Namespace: c.namespace,
			Labels: map[string]string{
				sandbox.ManagedByLabel:   sandbox.ManagedByValue,
				sandbox.SandboxNameLabel: sb.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: sandbox.SandboxGroupVersion.String(),
					Kind:       sandbox.SandboxKind,
					Name:       sb.Name,
					UID:        sb.UID,
				},
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			sandbox.TokenSecretKey: []byte(mintedToken),
		},
	}

	if _, err := c.kube.CoreV1().Secrets(c.namespace).Create(ctx, secretObj, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("create token secret %s/%s: %w", c.namespace, secretObj.Name, err)
	}
	return nil
}
