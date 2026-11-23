package gateway

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/leomcl/ada/internal/sandbox"
	"github.com/leomcl/ada/internal/token"
)

type stubSandboxStore struct {
	mu        sync.Mutex
	synced    bool
	active    map[string]string
	deleteErr error
	deleted   []string
}

func (s *stubSandboxStore) HasSynced() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.synced
}

func (s *stubSandboxStore) IsActive(name, repo string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	got, ok := s.active[name]
	return ok && repo != "" && got == repo
}

func (s *stubSandboxStore) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, name)
	delete(s.active, name)
	return nil
}

func newTestSandboxUnstructured(t *testing.T, name, repo string, managed bool, shutdownTime *time.Time) *unstructured.Unstructured {
	t.Helper()
	labels := map[string]string{}
	if managed {
		labels[sandbox.ManagedByLabel] = sandbox.ManagedByValue
		labels[sandbox.SandboxNameLabel] = name
	}
	sb := &sandbox.Sandbox{
		TypeMeta: metav1.TypeMeta{
			APIVersion: sandbox.SandboxGroupVersion.String(),
			Kind:       sandbox.SandboxKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: DefaultWorkloadsNamespace,
			UID:       types.UID("uid-" + name),
			Labels:    labels,
			Annotations: map[string]string{
				sandbox.RepoAnnotation: repo,
			},
		},
		Spec: sandbox.SandboxSpec{
			OperatingMode: sandbox.SandboxOperatingModeRunning,
		},
	}
	if shutdownTime != nil {
		sb.Spec.Lifecycle.ShutdownTime = ptr.To(metav1.NewTime(*shutdownTime))
	}
	u, err := sandbox.ToUnstructured(sb)
	if err != nil {
		t.Fatalf("ToUnstructured(%s): %v", name, err)
	}
	return u
}

func newFakeDynamicClient(t *testing.T, objects ...*unstructured.Unstructured) *dynamicfake.FakeDynamicClient {
	t.Helper()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			sandbox.SandboxGVR: "SandboxList",
		},
	)
	for _, obj := range objects {
		if err := client.Tracker().Create(sandbox.SandboxGVR, obj, obj.GetNamespace()); err != nil {
			t.Fatalf("seed fake dynamic client (%s): %v", obj.GetName(), err)
		}
	}
	return client
}

func waitFor(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

func startTestController(t *testing.T, cfg SandboxControllerConfig) *SandboxController {
	t.Helper()
	ctrl, err := NewSandboxController(cfg)
	if err != nil {
		t.Fatalf("NewSandboxController: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctrl.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitFor(t, 3*time.Second, "informer sync", ctrl.HasSynced)
	return ctrl
}

func TestSandboxControllerInitialListAndLiveAddMintsTokenSecret(t *testing.T) {
	signingKey := []byte("controller-signing-key")
	fixedNow := time.Now().UTC().Truncate(time.Second)
	preShutdown := fixedNow.Add(4 * time.Hour)

	preExisting := newTestSandboxUnstructured(t, "sb-pre", "leomcl/ada", true, &preShutdown)
	unmanaged := newTestSandboxUnstructured(t, "sb-other", "leomcl/ada", false, &preShutdown)

	kubeClient := kubefake.NewSimpleClientset()
	dynamicClient := newFakeDynamicClient(t, preExisting, unmanaged)

	ctrl := startTestController(t, SandboxControllerConfig{
		Namespace:  DefaultWorkloadsNamespace,
		SigningKey: signingKey,
		Kube:       kubeClient,
		Dynamic:    dynamicClient,
		Now:        func() time.Time { return fixedNow },
	})

	waitFor(t, 3*time.Second, "sb-pre token secret", func() bool {
		_, err := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-pre"), metav1.GetOptions{})
		return err == nil
	})

	preSecret, err := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-pre"), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get sb-pre token secret: %v", err)
	}
	claims, err := token.VerifySandboxToken(string(preSecret.Data[sandbox.TokenSecretKey]), signingKey, fixedNow)
	if err != nil {
		t.Fatalf("VerifySandboxToken(sb-pre): %v", err)
	}
	if claims.JTI != "sb-pre" || claims.Repo != "leomcl/ada" || claims.ExpiresAt != preShutdown.Unix() {
		t.Fatalf("unexpected sb-pre claims: %+v", claims)
	}
	if len(preSecret.OwnerReferences) != 1 {
		t.Fatalf("expected 1 ownerReference, got %d", len(preSecret.OwnerReferences))
	}
	owner := preSecret.OwnerReferences[0]
	if owner.APIVersion != sandbox.SandboxGroupVersion.String() || owner.Kind != sandbox.SandboxKind || owner.Name != "sb-pre" || owner.UID != types.UID("uid-sb-pre") {
		t.Fatalf("unexpected ownerReference: %+v", owner)
	}
	if owner.Controller != nil || owner.BlockOwnerDeletion != nil {
		t.Fatalf("expected nil Controller and BlockOwnerDeletion, got %+v", owner)
	}

	if _, err := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-other"), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected unmanaged sandbox not to get a token secret, got err=%v", err)
	}
	if !ctrl.IsActive("sb-pre", "leomcl/ada") {
		t.Fatal("expected sb-pre to be active")
	}
	if ctrl.IsActive("sb-pre", "leomcl/other") {
		t.Fatal("expected repo mismatch to report inactive")
	}
	if ctrl.IsActive("sb-other", "leomcl/ada") {
		t.Fatal("expected unmanaged sandbox to report inactive")
	}

	liveObj := newTestSandboxUnstructured(t, "sb-live", "leomcl/ada", true, nil)
	if _, err := dynamicClient.Resource(sandbox.SandboxGVR).Namespace(DefaultWorkloadsNamespace).Create(context.Background(), liveObj, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create sb-live: %v", err)
	}

	waitFor(t, 3*time.Second, "sb-live token secret", func() bool {
		_, err := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-live"), metav1.GetOptions{})
		return err == nil
	})

	liveSecret, err := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-live"), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get sb-live token secret: %v", err)
	}
	liveClaims, err := token.VerifySandboxToken(string(liveSecret.Data[sandbox.TokenSecretKey]), signingKey, fixedNow)
	if err != nil {
		t.Fatalf("VerifySandboxToken(sb-live): %v", err)
	}
	if liveClaims.ExpiresAt != fixedNow.Add(sandbox.DefaultTokenTTL).Unix() {
		t.Fatalf("expected default TTL expiry %d, got %d", fixedNow.Add(sandbox.DefaultTokenTTL).Unix(), liveClaims.ExpiresAt)
	}
}

func TestSandboxControllerRetriesTransientSecretCreateFailure(t *testing.T) {
	signingKey := []byte("retry-signing-key")
	shutdown := time.Now().UTC().Add(time.Hour)
	sbObj := newTestSandboxUnstructured(t, "sb-retry", "leomcl/ada", true, &shutdown)

	kubeClient := kubefake.NewSimpleClientset()
	var attempts atomic.Int32
	kubeClient.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if attempts.Add(1) == 1 {
			return true, nil, errors.New("apiserver temporary unavailable")
		}
		return false, nil, nil
	})
	dynamicClient := newFakeDynamicClient(t, sbObj)

	startTestController(t, SandboxControllerConfig{
		Namespace:  DefaultWorkloadsNamespace,
		SigningKey: signingKey,
		Kube:       kubeClient,
		Dynamic:    dynamicClient,
	})

	waitFor(t, 3*time.Second, "retried token secret creation", func() bool {
		_, err := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-retry"), metav1.GetOptions{})
		return err == nil
	})
	if attempts.Load() < 2 {
		t.Fatalf("expected at least 2 create attempts, got %d", attempts.Load())
	}
}

func TestGatewayRejectsRequestsBeforeInformerSynced(t *testing.T) {
	store := &stubSandboxStore{
		synced: false,
		active: map[string]string{
			"sandbox-1": "leomcl/better-branch",
		},
	}
	h := newTestHarnessWithConfig(t, func(cfg *Config) {
		cfg.Sandboxes = store
	})

	resp, err := h.gatewayServer.Client().Get(h.gatewayServer.URL + "/livez")
	if err != nil {
		t.Fatalf("GET /livez: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for /livez before sync, got %d", resp.StatusCode)
	}

	resp, err = h.gatewayServer.Client().Get(h.gatewayServer.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for /healthz before sync, got %d", resp.StatusCode)
	}

	if status := h.do(t, http.MethodGet, "/v1/models", nil); status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for /v1/models before sync, got %d", status)
	}
	if status := h.do(t, http.MethodDelete, "/sandbox/self", nil); status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for DELETE /sandbox/self before sync, got %d", status)
	}

	store.mu.Lock()
	store.synced = true
	store.mu.Unlock()

	resp, err = h.gatewayServer.Client().Get(h.gatewayServer.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz after sync: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for /healthz after sync, got %d", resp.StatusCode)
	}
	if status := h.do(t, http.MethodGet, "/v1/models", nil); status != http.StatusOK {
		t.Fatalf("expected 200 for active sandbox after sync, got %d", status)
	}

	store.mu.Lock()
	delete(store.active, "sandbox-1")
	store.mu.Unlock()

	if status := h.do(t, http.MethodGet, "/v1/models", nil); status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked sandbox, got %d", status)
	}
}

func TestGatewayAllowListRevocationAndDeleteSelfWithController(t *testing.T) {
	signingKey := []byte("gateway-test-signing-key")
	shutdown := time.Now().UTC().Add(time.Hour)
	sb1 := newTestSandboxUnstructured(t, "sb-1", "leomcl/ada", true, &shutdown)
	sb2 := newTestSandboxUnstructured(t, "sb-2", "leomcl/ada", true, &shutdown)

	kubeClient := kubefake.NewSimpleClientset()
	dynamicClient := newFakeDynamicClient(t, sb1, sb2)
	ctrl := startTestController(t, SandboxControllerConfig{
		Namespace:  DefaultWorkloadsNamespace,
		SigningKey: signingKey,
		Kube:       kubeClient,
		Dynamic:    dynamicClient,
	})

	waitFor(t, 3*time.Second, "sb-1 and sb-2 token secrets", func() bool {
		_, err1 := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-1"), metav1.GetOptions{})
		_, err2 := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-2"), metav1.GetOptions{})
		return err1 == nil && err2 == nil
	})

	secret1, err := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-1"), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get sb-1 secret: %v", err)
	}
	secret2, err := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-2"), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get sb-2 secret: %v", err)
	}

	h := newTestHarnessWithConfig(t, func(cfg *Config) {
		cfg.Secrets.SigningKey = signingKey
		cfg.Sandboxes = ctrl
	})

	doWithToken := func(method, path, tok string) int {
		t.Helper()
		req, err := http.NewRequest(method, h.gatewayServer.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := h.gatewayServer.Client().Do(req)
		if err != nil {
			t.Fatalf("Do %s %s: %v", method, path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	tok1 := string(secret1.Data[sandbox.TokenSecretKey])
	tok2 := string(secret2.Data[sandbox.TokenSecretKey])

	if status := doWithToken(http.MethodGet, "/v1/models", tok1); status != http.StatusOK {
		t.Fatalf("expected 200 for running sb-1, got %d", status)
	}

	// Non-Running operatingMode revokes access immediately.
	u, err := dynamicClient.Resource(sandbox.SandboxGVR).Namespace(DefaultWorkloadsNamespace).Get(context.Background(), "sb-1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get sb-1: %v", err)
	}
	parsed, err := sandbox.FromUnstructured(u)
	if err != nil {
		t.Fatalf("FromUnstructured: %v", err)
	}
	parsed.Spec.OperatingMode = "Shutdown"
	updated, err := sandbox.ToUnstructured(parsed)
	if err != nil {
		t.Fatalf("ToUnstructured: %v", err)
	}
	if _, err := dynamicClient.Resource(sandbox.SandboxGVR).Namespace(DefaultWorkloadsNamespace).Update(context.Background(), updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update sb-1 to Shutdown: %v", err)
	}
	waitFor(t, 3*time.Second, "sb-1 inactive", func() bool { return !ctrl.IsActive("sb-1", "leomcl/ada") })

	if status := doWithToken(http.MethodGet, "/v1/models", tok1); status != http.StatusUnauthorized {
		t.Fatalf("expected 401 when sb-1 is not Running, got %d", status)
	}

	// Returning to Running restores access.
	parsed.Spec.OperatingMode = sandbox.SandboxOperatingModeRunning
	updated, err = sandbox.ToUnstructured(parsed)
	if err != nil {
		t.Fatalf("ToUnstructured(running): %v", err)
	}
	if _, err := dynamicClient.Resource(sandbox.SandboxGVR).Namespace(DefaultWorkloadsNamespace).Update(context.Background(), updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update sb-1 to Running: %v", err)
	}
	waitFor(t, 3*time.Second, "sb-1 active again", func() bool { return ctrl.IsActive("sb-1", "leomcl/ada") })

	if status := doWithToken(http.MethodGet, "/sandbox/self", tok1); status != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET /sandbox/self, got %d", status)
	}
	if status := doWithToken(http.MethodDelete, "/sandbox/self", ""); status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated DELETE /sandbox/self, got %d", status)
	}

	// DELETE /sandbox/self deletes only sb-1 and writes an audit record.
	if status := doWithToken(http.MethodDelete, "/sandbox/self", tok1); status != http.StatusNoContent {
		t.Fatalf("expected 204 for DELETE /sandbox/self, got %d", status)
	}
	waitFor(t, 3*time.Second, "sb-1 deleted from cache", func() bool { return !ctrl.IsActive("sb-1", "leomcl/ada") })

	if _, err := dynamicClient.Resource(sandbox.SandboxGVR).Namespace(DefaultWorkloadsNamespace).Get(context.Background(), "sb-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected sb-1 to be deleted, got err=%v", err)
	}
	if _, err := dynamicClient.Resource(sandbox.SandboxGVR).Namespace(DefaultWorkloadsNamespace).Get(context.Background(), "sb-2", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected sb-2 to remain untouched, got err=%v", err)
	}
	if status := doWithToken(http.MethodGet, "/v1/models", tok1); status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for deleted sb-1 token, got %d", status)
	}
	if status := doWithToken(http.MethodGet, "/v1/models", tok2); status != http.StatusOK {
		t.Fatalf("expected 200 for unaffected sb-2 token, got %d", status)
	}

	recs := h.auditRecords(t)
	if len(recs) != 1 {
		t.Fatalf("expected 1 sandbox_delete audit record, got %d: %+v", len(recs), recs)
	}
	if recs[0]["event"] != "sandbox_delete" || recs[0]["decision"] != "allow" || recs[0]["sandbox"] != "sb-1" || recs[0]["repo"] != "leomcl/ada" || recs[0]["status"] != float64(http.StatusNoContent) {
		t.Fatalf("unexpected sandbox_delete audit record: %+v", recs[0])
	}
}

func TestDeleteSelfNotFoundAndErrorAudit(t *testing.T) {
	store := &stubSandboxStore{
		synced: true,
		active: map[string]string{
			"sandbox-1": "leomcl/better-branch",
		},
		deleteErr: apierrors.NewNotFound(sandbox.SandboxGVR.GroupResource(), "sandbox-1"),
	}
	h := newTestHarnessWithConfig(t, func(cfg *Config) {
		cfg.Sandboxes = store
	})

	if status := h.do(t, http.MethodDelete, "/sandbox/self", nil); status != http.StatusNotFound {
		t.Fatalf("expected 404 when sandbox already gone, got %d", status)
	}

	recs := h.auditRecords(t)
	if len(recs) != 1 || recs[0]["event"] != "sandbox_delete" || recs[0]["decision"] != "error" || recs[0]["reason"] != "not_found" || recs[0]["status"] != float64(http.StatusNotFound) {
		t.Fatalf("unexpected not_found audit record: %+v", recs)
	}
}

func TestSandboxControllerMintsTokenOnTransitionToRunningAndRejectsEmptyRepo(t *testing.T) {
	signingKey := []byte("transition-signing-key")
	shutdown := time.Now().UTC().Add(time.Hour)

	stoppedObj := newTestSandboxUnstructured(t, "sb-stopped", "leomcl/ada", true, &shutdown)
	if err := unstructured.SetNestedField(stoppedObj.Object, "Shutdown", "spec", "operatingMode"); err != nil {
		t.Fatalf("SetNestedField(operatingMode): %v", err)
	}
	noRepoObj := newTestSandboxUnstructured(t, "sb-no-repo", "", true, &shutdown)
	noRepoObj.SetAnnotations(nil)

	kubeClient := kubefake.NewSimpleClientset()
	dynamicClient := newFakeDynamicClient(t, stoppedObj, noRepoObj)

	ctrl := startTestController(t, SandboxControllerConfig{
		Namespace:  DefaultWorkloadsNamespace,
		SigningKey: signingKey,
		Kube:       kubeClient,
		Dynamic:    dynamicClient,
	})

	if ctrl.IsActive("sb-no-repo", "") {
		t.Fatal("expected IsActive to reject empty repo even when annotation is absent")
	}
	if ctrl.IsActive("sb-stopped", "leomcl/ada") {
		t.Fatal("expected stopped sandbox to report inactive")
	}
	if _, err := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-stopped"), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected no token secret while stopped, got err=%v", err)
	}

	u, err := dynamicClient.Resource(sandbox.SandboxGVR).Namespace(DefaultWorkloadsNamespace).Get(context.Background(), "sb-stopped", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get sb-stopped: %v", err)
	}
	if err := unstructured.SetNestedField(u.Object, string(sandbox.SandboxOperatingModeRunning), "spec", "operatingMode"); err != nil {
		t.Fatalf("SetNestedField(Running): %v", err)
	}
	if _, err := dynamicClient.Resource(sandbox.SandboxGVR).Namespace(DefaultWorkloadsNamespace).Update(context.Background(), u, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update sb-stopped to Running: %v", err)
	}

	waitFor(t, 3*time.Second, "sb-stopped token secret after transition to Running", func() bool {
		_, err := kubeClient.CoreV1().Secrets(DefaultWorkloadsNamespace).Get(context.Background(), sandbox.TokenSecretName("sb-stopped"), metav1.GetOptions{})
		return err == nil
	})
	waitFor(t, 3*time.Second, "sb-stopped active", func() bool {
		return ctrl.IsActive("sb-stopped", "leomcl/ada")
	})
}
