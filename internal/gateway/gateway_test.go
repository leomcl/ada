package gateway

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

type testHarness struct {
	gatewayServer     *httptest.Server
	githubUpstream    *mockUpstream
	githubAPIUpstream *mockUpstream
	cliproxyUpstream  *mockUpstream
	token             string
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	signingKey := []byte("gateway-test-signing-key")
	githubUpstream := newMockUpstream(t, "git-ok")
	githubAPIUpstream := newMockUpstream(t, "api-ok")
	cliproxyUpstream := newMockUpstream(t, "model-ok")

	handler, err := NewHandler(Config{
		SigningKey:       signingKey,
		GitHubPAT:        "ghp_real_secret_pat\n",
		GitHubBaseURL:    githubUpstream.server.URL,
		GitHubAPIBaseURL: githubAPIUpstream.server.URL,
		CLIProxyBaseURL:  cliproxyUpstream.server.URL,
		CLIProxyAPIKey:   "internal-cliproxy-key\n",
	})
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	gatewayServer := httptest.NewServer(handler)
	t.Cleanup(gatewayServer.Close)

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

	return &testHarness{
		gatewayServer:     gatewayServer,
		githubUpstream:    githubUpstream,
		githubAPIUpstream: githubAPIUpstream,
		cliproxyUpstream:  cliproxyUpstream,
		token:             tok,
	}
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
		if _, err := readReceivePackCommands(bytes.NewReader(body)); !errors.Is(err, errMalformedReceivePack) {
			t.Fatalf("expected malformed error for %q, got %v", body, err)
		}
	}

	consumed, err := readReceivePackCommands(bytes.NewReader([]byte("0000PACK")))
	if err != nil || string(consumed) != "0000" {
		t.Fatalf("expected flush-only probe to succeed, got consumed=%q err=%v", consumed, err)
	}
}
