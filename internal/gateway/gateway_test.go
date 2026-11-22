package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leomcl/ada/internal/token"
)

type recordedRequest struct {
	method  string
	uri     string
	headers http.Header
	body    []byte
}

type mockUpstream struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
}

func newMockUpstream(t *testing.T, responseBody string) *mockUpstream {
	t.Helper()
	m := &mockUpstream{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream request body: %v", err)
		}
		m.mu.Lock()
		m.requests = append(m.requests, recordedRequest{
			method:  r.Method,
			uri:     r.URL.RequestURI(),
			headers: r.Header.Clone(),
			body:    body,
		})
		m.mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, responseBody)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockUpstream) recorded() []recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]recordedRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type testHarness struct {
	gatewayServer     *httptest.Server
	githubUpstream    *mockUpstream
	githubAPIUpstream *mockUpstream
	cliproxyUpstream  *mockUpstream
	auditBuf          *syncBuffer
	inFlight          sync.WaitGroup
	token             string
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	return newTestHarnessWithConfig(t, func(cfg *Config) {})
}

func newTestHarnessWithConfig(t *testing.T, customize func(*Config)) *testHarness {
	t.Helper()
	signingKey := []byte("gateway-test-signing-key")
	githubUpstream := newMockUpstream(t, "git-ok")
	githubAPIUpstream := newMockUpstream(t, "api-ok")
	cliproxyUpstream := newMockUpstream(t, "model-ok")
	auditBuf := &syncBuffer{}

	cfg := Config{
		Settings: Settings{
			GitHub: GitHubSettings{
				BaseURL:    githubUpstream.server.URL,
				APIBaseURL: githubAPIUpstream.server.URL,
			},
			CLIProxy: CLIProxySettings{
				Enabled: true,
				BaseURL: cliproxyUpstream.server.URL,
			},
		},
		Secrets: Secrets{
			SigningKey:     signingKey,
			GitHubPAT:      "ghp_real_secret_pat\n",
			CLIProxyAPIKey: "internal-cliproxy-key\n",
		},
		AuditLogger: slog.New(slog.NewJSONHandler(auditBuf, nil)),
	}
	customize(&cfg)

	handler, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	h := &testHarness{
		githubUpstream:    githubUpstream,
		githubAPIUpstream: githubAPIUpstream,
		cliproxyUpstream:  cliproxyUpstream,
		auditBuf:          auditBuf,
	}

	h.gatewayServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.inFlight.Add(1)
		defer h.inFlight.Done()
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(h.gatewayServer.Close)

	now := time.Now()
	tok, err := token.MintSandboxToken(token.SandboxTokenClaims{
		JTI:       "sandbox-1",
		Repo:      "leomcl/better-branch",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	}, signingKey)
	if err != nil {
		t.Fatalf("MintSandboxToken failed: %v", err)
	}
	h.token = tok
	return h
}

func (h *testHarness) auditRecords(t *testing.T) []map[string]any {
	t.Helper()
	h.inFlight.Wait()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(h.auditBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unmarshal audit log line %q: %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}

func pktLine(payload string) []byte {
	return []byte(fmt.Sprintf("%04x%s", len(payload)+4, payload))
}

func receivePackBody(refs ...string) []byte {
	var buf bytes.Buffer
	for i, refName := range refs {
		if i == 0 {
			buf.Write(pktLine(fmt.Sprintf(
				"0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 %s\x00report-status\n",
				refName,
			)))
		} else {
			buf.Write(pktLine(fmt.Sprintf(
				"0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 %s\n",
				refName,
			)))
		}
	}
	buf.WriteString("0000PACK")
	return buf.Bytes()
}

func TestRejectsUnauthenticatedRequests(t *testing.T) {
	h := newTestHarness(t)
	client := h.gatewayServer.Client()

	resp, err := client.Get(h.gatewayServer.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for /v1/models, got %d", resp.StatusCode)
	}

	gitResp, err := client.Get(h.gatewayServer.URL + "/github/leomcl/better-branch.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET git info/refs: %v", err)
	}
	gitResp.Body.Close()
	if gitResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for git info/refs, got %d", gitResp.StatusCode)
	}
	if got := gitResp.Header.Get("WWW-Authenticate"); got != `Basic realm="ada-gateway"` {
		t.Fatalf("expected WWW-Authenticate header, got %q", got)
	}
}

func TestAllowsScopedGitCloneAndSwapsPAT(t *testing.T) {
	h := newTestHarness(t)
	req, err := http.NewRequest(http.MethodGet, h.gatewayServer.URL+"/github/leomcl/better-branch.git/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth("x-access-token", h.token)

	resp, err := h.gatewayServer.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK || string(body) != "git-ok" {
		t.Fatalf("unexpected response: %d %q", resp.StatusCode, string(body))
	}

	recorded := h.githubUpstream.recorded()
	if len(recorded) != 1 {
		t.Fatalf("expected 1 upstream request, got %d", len(recorded))
	}
	if recorded[0].method != http.MethodGet || recorded[0].uri != "/leomcl/better-branch.git/info/refs?service=git-upload-pack" {
		t.Fatalf("unexpected upstream request: %s %s", recorded[0].method, recorded[0].uri)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghp_real_secret_pat"))
	if gotAuth := recorded[0].headers.Get("Authorization"); gotAuth != wantAuth {
		t.Fatalf("expected Authorization %q, got %q", wantAuth, gotAuth)
	}
}

func TestRejectsUnauthorizedRepoGitRequest(t *testing.T) {
	h := newTestHarness(t)
	req, err := http.NewRequest(http.MethodGet, h.gatewayServer.URL+"/github/leomcl/other-repo.git/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth("x-access-token", h.token)

	resp, err := h.gatewayServer.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	if len(h.githubUpstream.recorded()) != 0 {
		t.Fatal("upstream should not receive unauthorized repo request")
	}
}

func TestBlocksGitPushToMainAndMaster(t *testing.T) {
	h := newTestHarness(t)
	cases := [][]string{
		{"refs/heads/main"},
		{"refs/heads/master"},
		{"refs/heads/feat/ok", "refs/heads/main"},
	}

	for _, refs := range cases {
		req, err := http.NewRequest(
			http.MethodPost,
			h.gatewayServer.URL+"/github/leomcl/better-branch.git/git-receive-pack",
			bytes.NewReader(receivePackBody(refs...)),
		)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.SetBasicAuth("x-access-token", h.token)

		resp, err := h.gatewayServer.Client().Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for refs %v, got %d", refs, resp.StatusCode)
		}
	}

	if len(h.githubUpstream.recorded()) != 0 {
		t.Fatal("upstream should not receive protected branch push")
	}
}

func TestAllowsGitPushToFeatureBranch(t *testing.T) {
	h := newTestHarness(t)
	payload := receivePackBody("refs/heads/feat/test")

	req, err := http.NewRequest(
		http.MethodPost,
		h.gatewayServer.URL+"/github/leomcl/better-branch.git/git-receive-pack",
		bytes.NewReader(payload),
	)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth("x-access-token", h.token)

	resp, err := h.gatewayServer.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	recorded := h.githubUpstream.recorded()
	if len(recorded) != 1 || recorded[0].method != http.MethodPost || !bytes.Equal(recorded[0].body, payload) {
		t.Fatalf("unexpected recorded push: %+v", recorded)
	}
}

func (h *testHarness) do(t *testing.T, method, path string, body []byte) int {
	t.Helper()
	req, err := http.NewRequest(method, h.gatewayServer.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	resp, err := h.gatewayServer.Client().Do(req)
	if err != nil {
		t.Fatalf("Do %s %s: %v", method, path, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestRejectsNonGitOperationsOnGitRoute(t *testing.T) {
	h := newTestHarness(t)
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/github/leomcl/better-branch/settings"},
		{http.MethodGet, "/github/leomcl/better-branch/archive/refs/heads/main.zip"},
		{http.MethodPost, "/github/leomcl/better-branch.git/info/refs"},
		{http.MethodGet, "/github/leomcl/better-branch.git/git-receive-pack"},
	}
	for _, tc := range cases {
		if status := h.do(t, tc.method, tc.path, nil); status != http.StatusForbidden {
			t.Fatalf("expected 403 for %s %s, got %d", tc.method, tc.path, status)
		}
	}
	if len(h.githubUpstream.recorded()) != 0 {
		t.Fatal("upstream should not receive non-git operations")
	}
}

func TestProxiesModelRoutesAndReplacesAuthHeader(t *testing.T) {
	h := newTestHarness(t)
	client := h.gatewayServer.Client()

	cases := []struct {
		method       string
		path         string
		header       string
		value        string
		body         string
		upstreamPath string
	}{
		{http.MethodGet, "/v1/models", "Authorization", "Bearer " + h.token, "", "/v1/models"},
		{http.MethodPost, "/anthropic/v1/messages", "x-api-key", h.token, `{"model":"claude"}`, "/v1/messages"},
		{http.MethodPost, "/google/v1beta/models", "x-goog-api-key", h.token, "", "/v1beta/models"},
		{http.MethodGet, "/google/v1beta/models?alt=json&key=" + h.token, "", "", "", "/v1beta/models?alt=json"},
	}

	for _, tc := range cases {
		req, err := http.NewRequest(tc.method, h.gatewayServer.URL+tc.path, strings.NewReader(tc.body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if tc.header != "" {
			req.Header.Set(tc.header, tc.value)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do %s: %v", tc.path, err)
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK || string(bodyBytes) != "model-ok" {
			t.Fatalf("unexpected model response for %s: %d %q", tc.path, resp.StatusCode, string(bodyBytes))
		}
	}

	recorded := h.cliproxyUpstream.recorded()
	if len(recorded) != len(cases) {
		t.Fatalf("expected %d upstream requests, got %d", len(cases), len(recorded))
	}
	for i, tc := range cases {
		if recorded[i].method != tc.method || recorded[i].uri != tc.upstreamPath {
			t.Fatalf("request %d mismatch: got %s %s, want %s %s", i, recorded[i].method, recorded[i].uri, tc.method, tc.upstreamPath)
		}
		if got := recorded[i].headers.Get("Authorization"); got != "Bearer internal-cliproxy-key" {
			t.Fatalf("request %d auth mismatch: %q", i, got)
		}
		if recorded[i].headers.Get("x-api-key") != "" || recorded[i].headers.Get("x-goog-api-key") != "" {
			t.Fatalf("request %d leaked client api key headers", i)
		}
	}
}

func TestRejectsDisallowedModelRoutesAndMethods(t *testing.T) {
	h := newTestHarness(t)
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/anthropic/v0/management/config"},
		{http.MethodPost, "/google/admin/oauth"},
		{http.MethodDelete, "/v1/models"},
		{http.MethodPut, "/anthropic/v1/messages"},
		{http.MethodGet, "/anthropic/v1/..%5cv0/management"},
	}

	for _, tc := range cases {
		if status := h.do(t, tc.method, tc.path, nil); status != http.StatusForbidden {
			t.Fatalf("expected 403 for %s %s, got %d", tc.method, tc.path, status)
		}
	}
	if len(h.cliproxyUpstream.recorded()) != 0 {
		t.Fatal("upstream should not receive disallowed model requests")
	}
}

func TestScopesGitHubAPIRouteAndInjectsPAT(t *testing.T) {
	h := newTestHarness(t)

	allowed := []struct {
		method       string
		path         string
		upstreamPath string
	}{
		{http.MethodGet, "/github-api/repos/leomcl/better-branch/pulls?state=open", "/repos/leomcl/better-branch/pulls?state=open"},
		{http.MethodGet, "/github-api/repos/leomcl/better-branch", "/repos/leomcl/better-branch"},
		{http.MethodPost, "/github-api/repos/leomcl/better-branch/pulls", "/repos/leomcl/better-branch/pulls"},
		{http.MethodPatch, "/github-api/repos/leomcl/better-branch/pulls/7", "/repos/leomcl/better-branch/pulls/7"},
		{http.MethodPost, "/github-api/repos/leomcl/better-branch/issues/7/comments", "/repos/leomcl/better-branch/issues/7/comments"},
	}
	for _, tc := range allowed {
		if status := h.do(t, tc.method, tc.path, nil); status != http.StatusOK {
			t.Fatalf("expected 200 for %s %s, got %d", tc.method, tc.path, status)
		}
	}

	forbidden := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/github-api/repos/leomcl/other-repo"},
		{http.MethodPatch, "/github-api/repos/leomcl/better-branch/git/refs/heads/main"},
		{http.MethodPut, "/github-api/repos/leomcl/better-branch/pulls/7/merge"},
		{http.MethodPut, "/github-api/repos/leomcl/better-branch/contents/README.md"},
		{http.MethodPost, "/github-api/repos/leomcl/better-branch/merges"},
		{http.MethodDelete, "/github-api/repos/leomcl/better-branch"},
		{http.MethodPatch, "/github-api/repos/leomcl/better-branch"},
		{http.MethodDelete, "/github-api/repos/leomcl/better-branch/branches/main/protection"},
	}
	for _, tc := range forbidden {
		if status := h.do(t, tc.method, tc.path, nil); status != http.StatusForbidden {
			t.Fatalf("expected 403 for %s %s, got %d", tc.method, tc.path, status)
		}
	}

	recorded := h.githubAPIUpstream.recorded()
	if len(recorded) != len(allowed) {
		t.Fatalf("expected %d upstream api requests, got %d", len(allowed), len(recorded))
	}
	for i, tc := range allowed {
		if recorded[i].method != tc.method || recorded[i].uri != tc.upstreamPath {
			t.Fatalf("api request %d mismatch: got %s %s, want %s %s", i, recorded[i].method, recorded[i].uri, tc.method, tc.upstreamPath)
		}
	}
	if got := recorded[0].headers.Get("Authorization"); got != "Bearer ghp_real_secret_pat" {
		t.Fatalf("expected Bearer PAT, got %q", got)
	}
}

func TestHealthz(t *testing.T) {
	h := newTestHarness(t)
	resp, err := h.gatewayServer.Client().Get(h.gatewayServer.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestReadReceivePackCommandsMalformed(t *testing.T) {
	invalidCases := [][]byte{
		[]byte(""),
		[]byte("+004"),
		[]byte("0x04"),
		[]byte("0003"),
		[]byte("0010short"),
		pktLine("only-two-fields refs/heads/feat\n"),
	}
	for _, body := range invalidCases {
		if _, _, err := readReceivePackCommands(bytes.NewReader(body)); !errors.Is(err, errMalformedReceivePack) {
			t.Fatalf("expected malformed error for %q, got %v", body, err)
		}
	}

	consumed, updates, err := readReceivePackCommands(bytes.NewReader([]byte("0000PACK")))
	if err != nil || string(consumed) != "0000" || len(updates) != 0 {
		t.Fatalf("expected flush-only probe to succeed, got consumed=%q updates=%v err=%v", consumed, updates, err)
	}
}

func TestLoadSettings(t *testing.T) {
	dir := t.TempDir()

	validPath := filepath.Join(dir, "gateway.yaml")
	validYAML := `
listenAddr: ":8080"
cliproxy:
  enabled: true
providers:
  openai:
    upstreamURL: https://openrouter.ai/api
`
	if err := os.WriteFile(validPath, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := LoadSettings(validPath)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.ListenAddr != ":8080" || !got.CLIProxy.Enabled || got.CLIProxy.BaseURL != DefaultCLIProxyBaseURL {
		t.Fatalf("unexpected gateway settings: %+v", got)
	}
	if got.Providers.OpenAI.UpstreamURL != "https://openrouter.ai/api" {
		t.Fatalf("expected custom openai upstream, got %q", got.Providers.OpenAI.UpstreamURL)
	}
	if got.Providers.Anthropic.UpstreamURL != DefaultAnthropicUpstreamURL || got.Providers.Google.UpstreamURL != DefaultGoogleUpstreamURL {
		t.Fatalf("expected default anthropic/google upstreams, got %+v", got.Providers)
	}

	typoPath := filepath.Join(dir, "typo.yaml")
	if err := os.WriteFile(typoPath, []byte("cliproxy:\n  enabeld: true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile typo: %v", err)
	}
	if _, err := LoadSettings(typoPath); err == nil {
		t.Fatal("expected strict YAML unmarshal to reject unknown field")
	}
}

func TestDirectProviderRoutingWithoutCLIProxy(t *testing.T) {
	openaiUpstream := newMockUpstream(t, "openai-ok")
	anthropicUpstream := newMockUpstream(t, "anthropic-ok")
	googleUpstream := newMockUpstream(t, "google-ok")

	h := newTestHarnessWithConfig(t, func(cfg *Config) {
		cfg.Settings.CLIProxy.Enabled = false
		cfg.Settings.Providers = ProviderSettings{
			OpenAI:    ProviderEndpoint{UpstreamURL: openaiUpstream.server.URL + "/api"},
			Anthropic: ProviderEndpoint{UpstreamURL: anthropicUpstream.server.URL},
			Google:    ProviderEndpoint{UpstreamURL: googleUpstream.server.URL},
		}
		cfg.Secrets.CLIProxyAPIKey = ""
		cfg.Secrets.OpenAIAPIKey = "sk-openai-real"
		cfg.Secrets.AnthropicAPIKey = "sk-ant-real"
		cfg.Secrets.GoogleAPIKey = "AIza-google-real"
	})

	client := h.gatewayServer.Client()

	openAIReq, _ := http.NewRequest(http.MethodPost, h.gatewayServer.URL+"/v1/chat/completions", strings.NewReader(`{"model":"gpt-5"}`))
	openAIReq.Header.Set("Authorization", "Bearer "+h.token)
	resp, err := client.Do(openAIReq)
	if err != nil {
		t.Fatalf("OpenAI request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "openai-ok" {
		t.Fatalf("unexpected OpenAI response: %d %q", resp.StatusCode, string(body))
	}

	anthropicReq, _ := http.NewRequest(http.MethodPost, h.gatewayServer.URL+"/anthropic/v1/messages", strings.NewReader(`{"model":"claude"}`))
	anthropicReq.Header.Set("x-api-key", h.token)
	anthropicReq.Header.Set("anthropic-version", "2023-06-01")
	resp, err = client.Do(anthropicReq)
	if err != nil {
		t.Fatalf("Anthropic request: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "anthropic-ok" {
		t.Fatalf("unexpected Anthropic response: %d %q", resp.StatusCode, string(body))
	}

	googleReq, _ := http.NewRequest(http.MethodGet, h.gatewayServer.URL+"/google/v1beta/models?alt=json&key="+h.token, nil)
	resp, err = client.Do(googleReq)
	if err != nil {
		t.Fatalf("Google request: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "google-ok" {
		t.Fatalf("unexpected Google response: %d %q", resp.StatusCode, string(body))
	}

	openaiRec := openaiUpstream.recorded()
	if len(openaiRec) != 1 || openaiRec[0].uri != "/api/v1/chat/completions" || openaiRec[0].headers.Get("Authorization") != "Bearer sk-openai-real" {
		t.Fatalf("unexpected OpenAI upstream call: %+v", openaiRec)
	}

	anthropicRec := anthropicUpstream.recorded()
	if len(anthropicRec) != 1 || anthropicRec[0].uri != "/v1/messages" || anthropicRec[0].headers.Get("x-api-key") != "sk-ant-real" || anthropicRec[0].headers.Get("anthropic-version") != "2023-06-01" || anthropicRec[0].headers.Get("Authorization") != "" {
		t.Fatalf("unexpected Anthropic upstream call: %+v", anthropicRec)
	}

	googleRec := googleUpstream.recorded()
	if len(googleRec) != 1 || googleRec[0].uri != "/v1beta/models?alt=json" || googleRec[0].headers.Get("x-goog-api-key") != "AIza-google-real" || googleRec[0].headers.Get("Authorization") != "" {
		t.Fatalf("unexpected Google upstream call: %+v", googleRec)
	}

	if len(h.cliproxyUpstream.recorded()) != 0 {
		t.Fatal("cliproxy should not be called when disabled")
	}
}

func TestHybridDirectAndCLIProxyRouting(t *testing.T) {
	openaiUpstream := newMockUpstream(t, "openai-direct")
	h := newTestHarnessWithConfig(t, func(cfg *Config) {
		cfg.Settings.Providers.OpenAI.UpstreamURL = openaiUpstream.server.URL
		cfg.Secrets.OpenAIAPIKey = "sk-openai-direct"
	})

	if status := h.do(t, http.MethodGet, "/v1/models", nil); status != http.StatusOK {
		t.Fatalf("expected 200 for /v1/models, got %d", status)
	}
	if status := h.do(t, http.MethodGet, "/google/v1beta/models", nil); status != http.StatusOK {
		t.Fatalf("expected 200 for /google/v1beta/models, got %d", status)
	}

	if len(openaiUpstream.recorded()) != 1 {
		t.Fatalf("expected 1 direct OpenAI call, got %d", len(openaiUpstream.recorded()))
	}
	cliproxyRec := h.cliproxyUpstream.recorded()
	if len(cliproxyRec) != 1 || cliproxyRec[0].uri != "/v1beta/models" {
		t.Fatalf("expected Google route to fall back to cliproxy, got %+v", cliproxyRec)
	}
}

func TestUnconfiguredProviderReturns503(t *testing.T) {
	h := newTestHarnessWithConfig(t, func(cfg *Config) {
		cfg.Settings.CLIProxy.Enabled = false
		cfg.Secrets.CLIProxyAPIKey = ""
	})

	if status := h.do(t, http.MethodGet, "/v1/models", nil); status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for unconfigured OpenAI provider, got %d", status)
	}
	if status := h.do(t, http.MethodPost, "/anthropic/v1/messages", nil); status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for unconfigured Anthropic provider, got %d", status)
	}
	if status := h.do(t, http.MethodGet, "/google/v1beta/models", nil); status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for unconfigured Google provider, got %d", status)
	}
	if status := h.do(t, http.MethodDelete, "/v1/models", nil); status != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed method before 503 check, got %d", status)
	}
}

func TestRejectsInvalidProviderUpstreamURL(t *testing.T) {
	for _, badURL := range []string{"not-a-url", "htps://api.openai.com", "ftp://api.openai.com", "https://"} {
		_, err := NewHandler(Config{
			Settings: Settings{
				Providers: ProviderSettings{
					OpenAI: ProviderEndpoint{UpstreamURL: badURL},
				},
			},
			Secrets: Secrets{
				SigningKey: []byte("gateway-test-signing-key"),
			},
		})
		if err == nil {
			t.Fatalf("expected error for invalid provider upstream URL %q", badURL)
		}
	}
}

func TestStatusRecorderIgnoresInformationalCodes(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	rec.WriteHeader(http.StatusContinue)
	rec.WriteHeader(http.StatusEarlyHints)
	if rec.status != 0 {
		t.Fatalf("expected 1xx codes to be ignored, got %d", rec.status)
	}
	rec.WriteHeader(http.StatusCreated)
	if rec.status != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rec.status)
	}

	wsRec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	wsRec.WriteHeader(http.StatusSwitchingProtocols)
	if wsRec.status != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 Switching Protocols to be recorded, got %d", wsRec.status)
	}
}

func TestAuditLogsGitPushAndGitHubAPIWrites(t *testing.T) {
	h := newTestHarness(t)

	if status := h.do(t, http.MethodGet, "/github-api/repos/leomcl/better-branch/pulls", nil); status != http.StatusOK {
		t.Fatalf("expected 200 for GET pulls, got %d", status)
	}
	if status := h.do(t, http.MethodGet, "/github/leomcl/other-repo.git/git-receive-pack", nil); status != http.StatusForbidden {
		t.Fatalf("expected 403 for GET other-repo git-receive-pack, got %d", status)
	}
	if recs := h.auditRecords(t); len(recs) != 0 {
		t.Fatalf("expected no audit logs for read-only GET or non-POST receive-pack, got %+v", recs)
	}

	if status := h.do(t, http.MethodPost, "/github/leomcl/better-branch.git/git-receive-pack", receivePackBody("refs/heads/feat/audit")); status != http.StatusOK {
		t.Fatalf("expected 200 for feature push, got %d", status)
	}

	deleteBody := bytes.NewBuffer(nil)
	deleteBody.Write(pktLine("1111111111111111111111111111111111111111 0000000000000000000000000000000000000000 refs/heads/feat/old\x00report-status\n"))
	deleteBody.WriteString("0000PACK")
	if status := h.do(t, http.MethodPost, "/github/leomcl/better-branch.git/git-receive-pack", deleteBody.Bytes()); status != http.StatusOK {
		t.Fatalf("expected 200 for branch delete push, got %d", status)
	}

	if status := h.do(t, http.MethodPost, "/github/leomcl/better-branch.git/git-receive-pack", receivePackBody("refs/heads/main")); status != http.StatusForbidden {
		t.Fatalf("expected 403 for protected push, got %d", status)
	}

	if status := h.do(t, http.MethodPost, "/github/leomcl/other-repo.git/git-receive-pack", receivePackBody("refs/heads/feat/x")); status != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong-repo push, got %d", status)
	}

	if status := h.do(t, http.MethodPost, "/github-api/repos/leomcl/better-branch/pulls", []byte(`{"title":"t"}`)); status != http.StatusOK {
		t.Fatalf("expected 200 for POST pulls, got %d", status)
	}
	if status := h.do(t, http.MethodPut, "/github-api/repos/leomcl/better-branch/pulls/7/merge", nil); status != http.StatusForbidden {
		t.Fatalf("expected 403 for PUT merge, got %d", status)
	}

	recs := h.auditRecords(t)
	if len(recs) != 6 {
		t.Fatalf("expected 6 audit records, got %d: %+v", len(recs), recs)
	}

	if recs[0]["event"] != "git_push" || recs[0]["decision"] != "allow" || recs[0]["sandbox"] != "sandbox-1" || recs[0]["ref"] != "refs/heads/feat/audit" || recs[0]["create"] != true || recs[0]["delete"] != false || recs[0]["status"] != float64(200) {
		t.Fatalf("unexpected create push audit record: %+v", recs[0])
	}
	if recs[1]["event"] != "git_push" || recs[1]["decision"] != "allow" || recs[1]["ref"] != "refs/heads/feat/old" || recs[1]["create"] != false || recs[1]["delete"] != true {
		t.Fatalf("unexpected delete push audit record: %+v", recs[1])
	}
	if recs[2]["event"] != "git_push" || recs[2]["decision"] != "deny" || recs[2]["reason"] != "protected_ref" || recs[2]["ref"] != "refs/heads/main" || recs[2]["status"] != float64(403) {
		t.Fatalf("unexpected denied push audit record: %+v", recs[2])
	}
	if recs[3]["event"] != "git_push" || recs[3]["decision"] != "deny" || recs[3]["reason"] != "forbidden_repo" || recs[3]["status"] != float64(403) {
		t.Fatalf("unexpected wrong-repo push audit record: %+v", recs[3])
	}
	if recs[4]["event"] != "github_api_write" || recs[4]["decision"] != "allow" || recs[4]["method"] != "POST" || recs[4]["path"] != "pulls" || recs[4]["status"] != float64(200) {
		t.Fatalf("unexpected allowed API write audit record: %+v", recs[4])
	}
	if recs[5]["event"] != "github_api_write" || recs[5]["decision"] != "deny" || recs[5]["reason"] != "forbidden_operation" || recs[5]["method"] != "PUT" || recs[5]["path"] != "pulls/7/merge" || recs[5]["status"] != float64(403) {
		t.Fatalf("unexpected denied API write audit record: %+v", recs[5])
	}
}

func TestAuditLogsEmittedOnAbortedUpstreamStream(t *testing.T) {
	abortedUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "partial")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
			}
		}
	}))
	t.Cleanup(abortedUpstream.Close)

	h := newTestHarnessWithConfig(t, func(cfg *Config) {
		cfg.Settings.GitHub.APIBaseURL = abortedUpstream.URL
	})

	req, _ := http.NewRequest(http.MethodPost, h.gatewayServer.URL+"/github-api/repos/leomcl/better-branch/pulls", strings.NewReader(`{"title":"t"}`))
	req.Header.Set("Authorization", "Bearer "+h.token)
	resp, err := h.gatewayServer.Client().Do(req)
	if err == nil {
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	recs := h.auditRecords(t)
	if len(recs) != 1 || recs[0]["event"] != "github_api_write" || recs[0]["decision"] != "allow" || recs[0]["path"] != "pulls" || recs[0]["status"] != float64(200) {
		t.Fatalf("expected deferred audit record on aborted stream, got %+v", recs)
	}
}
