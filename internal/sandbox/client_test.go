package sandbox

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/leomcl/ada/internal/token"
)

func newTestDynamicClient(t *testing.T) *dynamicfake.FakeDynamicClient {
	t.Helper()
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			SandboxGVR: "SandboxList",
		},
	)
	var seq atomic.Int64
	client.PrependReactor("create", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(k8stesting.CreateAction)
		if !ok {
			return false, nil, nil
		}
		u, ok := createAction.GetObject().(*unstructured.Unstructured)
		if !ok {
			return false, nil, nil
		}
		if u.GetUID() == "" {
			u.SetUID(types.UID("uid-" + string(rune('a'+seq.Add(1)-1))))
		}
		if ts := u.GetCreationTimestamp(); ts.IsZero() {
			u.SetCreationTimestamp(metav1.NewTime(time.Unix(1700000000, 0).UTC()))
		}
		return false, nil, nil
	})
	return client
}

func newTestClient(t *testing.T, objects ...runtime.Object) (*Client, *kubefake.Clientset, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	hasDefaultSecret := false
	for _, obj := range objects {
		if sec, ok := obj.(*corev1.Secret); ok && sec.Namespace == defaultSystemNamespace && sec.Name == defaultSigningKeySecretName {
			hasDefaultSecret = true
			break
		}
	}
	if !hasDefaultSecret {
		objects = append(objects, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      defaultSigningKeySecretName,
				Namespace: defaultSystemNamespace,
			},
			Data: map[string][]byte{
				signingKeySecretKey: []byte("cluster-signing-secret-key\n"),
			},
		})
	}
	kubeClient := kubefake.NewSimpleClientset(objects...)
	dynamicClient := newTestDynamicClient(t)
	return &Client{kube: kubeClient, dynamic: dynamicClient}, kubeClient, dynamicClient
}

func TestGenerateName(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z][a-z0-9-]*-[0-9a-f]{8}$`)

	nameA, err := GenerateName("leomcl/Better_Branch.git")
	if err != nil {
		t.Fatalf("GenerateName: %v", err)
	}
	nameB, err := GenerateName("leomcl/Better_Branch.git")
	if err != nil {
		t.Fatalf("GenerateName: %v", err)
	}

	if !strings.HasPrefix(nameA, "better-branch-") {
		t.Fatalf("expected prefix better-branch-, got %q", nameA)
	}
	if !pattern.MatchString(nameA) {
		t.Fatalf("invalid DNS label %q", nameA)
	}
	if nameA == nameB {
		t.Fatalf("expected unique names across calls, got duplicate %q", nameA)
	}

	numericName, err := GenerateName("org/123app")
	if err != nil {
		t.Fatalf("GenerateName(numeric): %v", err)
	}
	if !strings.HasPrefix(numericName, "s-123app-") {
		t.Fatalf("expected prefix s-123app-, got %q", numericName)
	}
	if !pattern.MatchString(numericName) {
		t.Fatalf("numeric repo did not produce valid DNS-1035 label: %q", numericName)
	}

	longRepo := "org/" + strings.Repeat("abcde-", 11)
	longName, err := GenerateName(longRepo)
	if err != nil {
		t.Fatalf("GenerateName(long): %v", err)
	}
	if len(longName) > 63 {
		t.Fatalf("name exceeded 63 chars: len=%d (%q)", len(longName), longName)
	}
	if strings.Contains(longName, "--") {
		t.Fatalf("truncated name kept trailing dash before suffix: %q", longName)
	}
	if !pattern.MatchString(longName) {
		t.Fatalf("invalid truncated DNS label %q", longName)
	}
}

func TestCreateSandboxAndSecret(t *testing.T) {
	ctx := context.Background()
	signingKey := []byte("cluster-signing-secret-key")
	client, kubeClient, _ := newTestClient(t)

	cfg := Defaults()
	cfg.Repo = "leomcl/better-branch.git"
	cfg.Access = "rex"
	cfg.Harness = "claude"
	cfg.Spot = true
	cfg.TailscaleAuthKey = "tskey-ephemeral-1"

	sb, err := client.Create(ctx, cfg)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if sb.Name == "" {
		t.Fatal("expected generated sandbox name")
	}
	secretName := sb.Name + "-token"

	secret, err := kubeClient.CoreV1().Secrets(defaultWorkloadNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get created secret: %v", err)
	}
	if gotTS := string(secret.Data["ts-authkey"]); gotTS != "tskey-ephemeral-1" {
		t.Fatalf("secret ts-authkey: got %q", gotTS)
	}

	claims, err := token.VerifySandboxToken(string(secret.Data["token"]), signingKey, time.Now())
	if err != nil {
		t.Fatalf("VerifySandboxToken: %v", err)
	}
	if claims.Repo != "leomcl/better-branch" {
		t.Fatalf("claims.Repo: got %q, want leomcl/better-branch", claims.Repo)
	}
	if claims.JTI != sb.Name {
		t.Fatalf("claims.JTI: got %q, want %q", claims.JTI, sb.Name)
	}
	if claims.ExpiresAt-claims.IssuedAt != int64((12 * time.Hour).Seconds()) {
		t.Fatalf("unexpected token TTL: %d", claims.ExpiresAt-claims.IssuedAt)
	}

	if len(secret.OwnerReferences) != 1 {
		t.Fatalf("expected 1 ownerReference on secret, got %d", len(secret.OwnerReferences))
	}
	owner := secret.OwnerReferences[0]
	if owner.APIVersion != "agents.x-k8s.io/v1beta1" || owner.Kind != "Sandbox" || owner.Name != sb.Name || owner.UID != sb.UID {
		t.Fatalf("unexpected ownerReference: %+v (sandbox UID=%s)", owner, sb.UID)
	}
	if owner.Controller != nil {
		t.Fatalf("expected OwnerReference.Controller to be nil, got %v", *owner.Controller)
	}

	podSpec := sb.Spec.PodTemplate.Spec
	if podSpec.RuntimeClassName == nil || *podSpec.RuntimeClassName != "gvisor" {
		t.Fatalf("expected runtimeClassName gvisor, got %v", podSpec.RuntimeClassName)
	}
	if podSpec.AutomountServiceAccountToken == nil || *podSpec.AutomountServiceAccountToken {
		t.Fatalf("expected automountServiceAccountToken=false, got %v", podSpec.AutomountServiceAccountToken)
	}
	if podSpec.NodeSelector[gkeSpotNodeSelectorKey] != "true" {
		t.Fatalf("expected spot nodeSelector, got %+v", podSpec.NodeSelector)
	}
	if !Spot(sb) {
		t.Fatal("expected Spot(sb) to be true")
	}
	if len(podSpec.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(podSpec.Containers))
	}

	container := podSpec.Containers[0]
	if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
		t.Fatalf("expected allowPrivilegeEscalation=false, got %+v", container.SecurityContext)
	}
	wantResources := map[corev1.ResourceName]string{
		corev1.ResourceCPU:              "2",
		corev1.ResourceMemory:           "4Gi",
		corev1.ResourceEphemeralStorage: "10Gi",
	}
	for resName, wantQty := range wantResources {
		want := resource.MustParse(wantQty)
		if got := container.Resources.Requests[resName]; !got.Equal(want) {
			t.Fatalf("resource request %s: got %s, want %s", resName, got.String(), want.String())
		}
		if got := container.Resources.Limits[resName]; !got.Equal(want) {
			t.Fatalf("resource limit %s: got %s, want %s", resName, got.String(), want.String())
		}
	}
	if container.ReadinessProbe == nil || container.ReadinessProbe.Exec == nil {
		t.Fatalf("expected exec ReadinessProbe on sandbox container, got %+v", container.ReadinessProbe)
	}
	wantProbeCmd := []string{"test", "-f", "/tmp/ada-ready"}
	if !reflect.DeepEqual(container.ReadinessProbe.Exec.Command, wantProbeCmd) {
		t.Fatalf("ReadinessProbe command: got %v, want %v", container.ReadinessProbe.Exec.Command, wantProbeCmd)
	}

	envMap := make(map[string]corev1.EnvVar)
	for _, ev := range container.Env {
		envMap[ev.Name] = ev
	}

	if _, exists := envMap["ANTHROPIC_API_KEY"]; exists {
		t.Fatal("ANTHROPIC_API_KEY should not be set when ANTHROPIC_AUTH_TOKEN is used")
	}

	for _, secretEnvName := range []string{"ADA_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN", "GEMINI_API_KEY"} {
		ev, ok := envMap[secretEnvName]
		if !ok {
			t.Fatalf("missing env %s", secretEnvName)
		}
		if ev.Value != "" {
			t.Fatalf("env %s must not embed inline token value", secretEnvName)
		}
		if ev.ValueFrom == nil || ev.ValueFrom.SecretKeyRef == nil ||
			ev.ValueFrom.SecretKeyRef.Name != secretName || ev.ValueFrom.SecretKeyRef.Key != "token" {
			t.Fatalf("env %s has unexpected secretKeyRef: %+v", secretEnvName, ev.ValueFrom)
		}
	}

	tsEnv := envMap["TS_AUTHKEY"]
	if tsEnv.ValueFrom == nil || tsEnv.ValueFrom.SecretKeyRef == nil || tsEnv.ValueFrom.SecretKeyRef.Key != "ts-authkey" {
		t.Fatalf("unexpected TS_AUTHKEY env: %+v", tsEnv)
	}

	wantPlain := map[string]string{
		"ADA_REPO":               "leomcl/better-branch",
		"ADA_SANDBOX_NAME":       sb.Name,
		"ACCESS":                 "rex",
		"HARNESS":                "claude",
		"ADA_GATEWAY":            defaultGatewayURL,
		"OPENAI_BASE_URL":        defaultGatewayURL + "/v1",
		"ANTHROPIC_BASE_URL":     defaultGatewayURL + "/anthropic",
		"GEMINI_API_BASE_URL":    defaultGatewayURL + "/google",
		"GOOGLE_GEMINI_BASE_URL": defaultGatewayURL + "/google",
	}
	for k, wantVal := range wantPlain {
		if got := envMap[k].Value; got != wantVal {
			t.Fatalf("env %s: got %q, want %q", k, got, wantVal)
		}
	}
}

func TestCreateDoesNotLeaveSecretOnSandboxError(t *testing.T) {
	ctx := context.Background()
	client, kubeClient, dynamicClient := newTestClient(t)
	dynamicClient.PrependReactor("create", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("webhook rejected sandbox")
	})

	cfg := Defaults()
	cfg.Repo = "leomcl/ada"
	cfg.SandboxName = "ada-fail"

	if _, err := client.Create(ctx, cfg); err == nil {
		t.Fatal("expected error when sandbox creation fails")
	}

	_, getErr := kubeClient.CoreV1().Secrets(defaultWorkloadNamespace).Get(ctx, "ada-fail-token", metav1.GetOptions{})
	if !apierrors.IsNotFound(getErr) {
		t.Fatalf("expected no secret to be created, got err=%v", getErr)
	}
}

func TestCreateCleansUpSandboxOnSecretError(t *testing.T) {
	ctx := context.Background()
	client, kubeClient, dynamicClient := newTestClient(t)
	kubeClient.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("secret quota exceeded")
	})

	cfg := Defaults()
	cfg.Repo = "leomcl/ada"
	cfg.SandboxName = "ada-secret-fail"

	if _, err := client.Create(ctx, cfg); err == nil {
		t.Fatal("expected error when secret creation fails")
	}

	_, getErr := dynamicClient.Resource(SandboxGVR).Namespace(defaultWorkloadNamespace).Get(ctx, "ada-secret-fail", metav1.GetOptions{})
	if !apierrors.IsNotFound(getErr) {
		t.Fatalf("expected sandbox to be cleaned up, got err=%v", getErr)
	}
}

func TestListAndDeleteSandboxes(t *testing.T) {
	ctx := context.Background()
	client, _, dynamicClient := newTestClient(t)

	cfg := Defaults()
	cfg.Repo = "leomcl/ada"
	cfg.SandboxName = "ada-one"
	cfg.Access = "tty"
	cfg.Harness = "opencode"

	if _, err := client.Create(ctx, cfg); err != nil {
		t.Fatalf("Create: %v", err)
	}

	unrelated := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": SandboxGroupVersion.String(),
			"kind":       SandboxKind,
			"metadata": map[string]any{
				"name":      "not-managed-by-ada",
				"namespace": defaultWorkloadNamespace,
			},
		},
	}
	if _, err := dynamicClient.Resource(SandboxGVR).Namespace(defaultWorkloadNamespace).Create(ctx, unrelated, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create unrelated sandbox: %v", err)
	}

	items, err := client.List(ctx, defaultWorkloadNamespace)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 ada-managed sandbox, got %d: %+v", len(items), items)
	}
	if items[0].Name != "ada-one" || items[0].Repo != "leomcl/ada" || items[0].Access != "tty" || items[0].Harness != "opencode" || items[0].Spot {
		t.Fatalf("unexpected summary: %+v", items[0])
	}

	if err := client.Delete(ctx, defaultWorkloadNamespace, "ada-one"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	itemsAfter, err := client.List(ctx, defaultWorkloadNamespace)
	if err != nil {
		t.Fatalf("List after delete: %v", err)
	}
	if len(itemsAfter) != 0 {
		t.Fatalf("expected 0 sandboxes after delete, got %d", len(itemsAfter))
	}
}

func TestWaitReady(t *testing.T) {
	ctx := context.Background()
	client, _, dynamicClient := newTestClient(t)

	cfg := Defaults()
	cfg.Repo = "leomcl/ada"
	cfg.SandboxName = "ada-wait"

	if _, err := client.Create(ctx, cfg); err != nil {
		t.Fatalf("Create: %v", err)
	}

	setStatusCondition := func(status metav1.ConditionStatus, reason, msg string) {
		u, err := dynamicClient.Resource(SandboxGVR).Namespace(defaultWorkloadNamespace).Get(ctx, "ada-wait", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("Get sandbox: %v", err)
		}
		sb, err := fromUnstructured(u)
		if err != nil {
			t.Fatalf("fromUnstructured: %v", err)
		}
		sb.Status.Conditions = []metav1.Condition{
			{
				Type:    string(SandboxConditionReady),
				Status:  status,
				Reason:  reason,
				Message: msg,
			},
		}
		updated, err := toUnstructured(sb)
		if err != nil {
			t.Fatalf("toUnstructured: %v", err)
		}
		if _, err := dynamicClient.Resource(SandboxGVR).Namespace(defaultWorkloadNamespace).UpdateStatus(ctx, updated, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("UpdateStatus: %v", err)
		}
	}

	setStatusCondition(metav1.ConditionTrue, "DependenciesReady", "ready")

	readyCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	sb, err := client.WaitReady(readyCtx, defaultWorkloadNamespace, "ada-wait")
	if err != nil {
		t.Fatalf("WaitReady(ready): %v", err)
	}
	if sb.Name != "ada-wait" {
		t.Fatalf("unexpected sandbox returned: %s", sb.Name)
	}

	setStatusCondition(metav1.ConditionFalse, SandboxReasonPodFailed, "OOMKilled")
	failCtx, cancelFail := context.WithTimeout(ctx, 3*time.Second)
	defer cancelFail()
	if _, err := client.WaitReady(failCtx, defaultWorkloadNamespace, "ada-wait"); err == nil || !strings.Contains(err.Error(), "PodFailed") {
		t.Fatalf("expected terminal PodFailed error, got %v", err)
	}
}
