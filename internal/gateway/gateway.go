package gateway

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/leomcl/ada/internal/token"
)

const maxReceivePackCommandBytes = 1 << 20

var (
	errMalformedReceivePack = errors.New("malformed receive-pack request")
	errProtectedRef         = errors.New("push to protected ref is forbidden")
)

var protectedRefs = map[string]bool{
	"HEAD":              true,
	"refs/heads/main":   true,
	"refs/heads/master": true,
}

var allowedGitHubAPIWrites = []struct {
	method      string
	pathPattern string
}{
	{http.MethodPost, "pulls"},
	{http.MethodPatch, "pulls/*"},
	{http.MethodPost, "pulls/*/comments"},
	{http.MethodPost, "pulls/*/reviews"},
	{http.MethodPost, "issues/*/comments"},
}

type Config struct {
	Settings    Settings
	Secrets     Secrets
	AuditLogger *slog.Logger
	Sandboxes   SandboxStore
}

type gateway struct {
	signingKey     []byte
	auditLogger    *slog.Logger
	sandboxes      SandboxStore
	githubProxy    *httputil.ReverseProxy
	githubAPIProxy *httputil.ReverseProxy
}

type providerRoute struct {
	name        string
	pattern     string
	routePrefix string
	upstreamURL string
	apiKey      string
	authHeader  string
	authPrefix  string
}

func NewHandler(cfg Config) (http.Handler, error) {
	signingKey, err := token.ParseSigningKey(cfg.Secrets.SigningKey)
	if err != nil {
		return nil, err
	}
	settings := cfg.Settings.withDefaults()
	secrets := cfg.Secrets.trimmed()

	githubURL, err := parseUpstreamURL(settings.GitHub.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid github.baseURL: %w", err)
	}
	githubAPIURL, err := parseUpstreamURL(settings.GitHub.APIBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid github.apiBaseURL: %w", err)
	}

	var cliproxyURL *url.URL
	if settings.CLIProxy.Enabled {
		cliproxyURL, err = parseUpstreamURL(settings.CLIProxy.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid cliproxy.baseURL: %w", err)
		}
	}

	auditLogger := cfg.AuditLogger
	if auditLogger == nil {
		auditLogger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}

	gitBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+secrets.GitHubPAT))

	gw := &gateway{
		signingKey:  signingKey,
		auditLogger: auditLogger,
		sandboxes:   cfg.Sandboxes,
		githubProxy: newReverseProxy(func(pr *httputil.ProxyRequest) {
			owner := pr.In.PathValue("owner")
			repo := pr.In.PathValue("repo")
			rest := pr.In.PathValue("path")
			setTargetPath(pr, githubURL, fmt.Sprintf("/%s/%s/%s", owner, repo, rest))
			stripClientAuthHeaders(pr.Out.Header)
			pr.Out.Header.Set("Authorization", gitBasicAuth)
		}),
		githubAPIProxy: newReverseProxy(func(pr *httputil.ProxyRequest) {
			owner := pr.In.PathValue("owner")
			repo := pr.In.PathValue("repo")
			rest := pr.In.PathValue("path")
			targetPath := fmt.Sprintf("/repos/%s/%s", owner, repo)
			if rest != "" {
				targetPath += "/" + rest
			}
			setTargetPath(pr, githubAPIURL, targetPath)
			stripClientAuthHeaders(pr.Out.Header)
			pr.Out.Header.Set("Authorization", "Bearer "+secrets.GitHubPAT)
			if pr.Out.Header.Get("User-Agent") == "" {
				pr.Out.Header.Set("User-Agent", "ada-gateway")
			}
		}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if gw.sandboxes != nil && !gw.sandboxes.HasSynced() {
			http.Error(w, "sandbox informer not synced", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("DELETE /sandbox/self", gw.handleDeleteSelf)
	mux.HandleFunc("/github/{owner}/{repo}/{path...}", gw.handleGitHubGit)
	mux.HandleFunc("/github-api/repos/{owner}/{repo}", gw.handleGitHubAPI)
	mux.HandleFunc("/github-api/repos/{owner}/{repo}/{path...}", gw.handleGitHubAPI)

	providers := []providerRoute{
		{
			name:        "openai",
			pattern:     "/v1/{path...}",
			upstreamURL: settings.Providers.OpenAI.UpstreamURL,
			apiKey:      secrets.OpenAIAPIKey,
			authHeader:  "Authorization",
			authPrefix:  "Bearer ",
		},
		{
			name:        "anthropic",
			pattern:     "/anthropic/{path...}",
			routePrefix: "/anthropic",
			upstreamURL: settings.Providers.Anthropic.UpstreamURL,
			apiKey:      secrets.AnthropicAPIKey,
			authHeader:  "x-api-key",
		},
		{
			name:        "google",
			pattern:     "/google/{path...}",
			routePrefix: "/google",
			upstreamURL: settings.Providers.Google.UpstreamURL,
			apiKey:      secrets.GoogleAPIKey,
			authHeader:  "x-goog-api-key",
		},
	}

	for _, p := range providers {
		upstreamURL, err := parseUpstreamURL(p.upstreamURL)
		if err != nil {
			return nil, fmt.Errorf("invalid providers.%s.upstreamURL: %w", p.name, err)
		}
		var proxy *httputil.ReverseProxy
		switch {
		case p.apiKey != "":
			authValue := p.authPrefix + p.apiKey
			proxy = newReverseProxy(func(pr *httputil.ProxyRequest) {
				setTargetPath(pr, upstreamURL, stripRoutePrefix(pr.In.URL.Path, p.routePrefix))
				stripClientAuthHeaders(pr.Out.Header)
				pr.Out.Header.Set(p.authHeader, authValue)
			})
		case cliproxyURL != nil:
			proxy = newReverseProxy(func(pr *httputil.ProxyRequest) {
				setTargetPath(pr, cliproxyURL, stripRoutePrefix(pr.In.URL.Path, p.routePrefix))
				stripClientAuthHeaders(pr.Out.Header)
				if secrets.CLIProxyAPIKey != "" {
					pr.Out.Header.Set("Authorization", "Bearer "+secrets.CLIProxyAPIKey)
				}
			})
		}
		mux.HandleFunc(p.pattern, gw.handleModelProxy(p.name, p.routePrefix, proxy))
	}

	return mux, nil
}

func (gw *gateway) handleGitHubGit(w http.ResponseWriter, r *http.Request) {
	claims, ok := gw.authenticate(w, r)
	if !ok {
		return
	}

	owner := r.PathValue("owner")
	repo := r.PathValue("repo")
	rest := r.PathValue("path")
	if !validSingleSegment(owner) || !validSingleSegment(repo) {
		http.Error(w, "invalid repository path", http.StatusBadRequest)
		return
	}
	targetRepo := owner + "/" + strings.TrimSuffix(repo, ".git")
	isPush := r.Method == http.MethodPost && rest == "git-receive-pack"
	if claims.Repo != targetRepo {
		if isPush {
			gw.logGitPushAudit(gitPushAudit{
				Decision: "deny",
				Reason:   "forbidden_repo",
				Sandbox:  claims.JTI,
				Repo:     targetRepo,
				Status:   http.StatusForbidden,
			})
		}
		http.Error(w, "forbidden repository", http.StatusForbidden)
		return
	}
	if !gitOperationAllowed(r.Method, rest) {
		http.Error(w, "forbidden git operation", http.StatusForbidden)
		return
	}

	if isPush {
		commands, updates, err := readReceivePackCommands(r.Body)
		if err != nil {
			gw.logGitPushAudit(gitPushAudit{
				Decision: "deny",
				Reason:   "malformed_receive_pack",
				Sandbox:  claims.JTI,
				Repo:     targetRepo,
				Status:   http.StatusBadRequest,
			})
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, update := range updates {
			if protectedRefs[update.Ref] {
				gw.logGitPushAudit(gitPushAudit{
					Decision: "deny",
					Reason:   "protected_ref",
					Sandbox:  claims.JTI,
					Repo:     targetRepo,
					Update:   update,
					Status:   http.StatusForbidden,
				})
				http.Error(w, fmt.Sprintf("%s: %s", errProtectedRef, update.Ref), http.StatusForbidden)
				return
			}
		}

		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(commands), r.Body), r.Body}

		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			for _, update := range updates {
				gw.logGitPushAudit(gitPushAudit{
					Decision: "allow",
					Sandbox:  claims.JTI,
					Repo:     targetRepo,
					Update:   update,
					Status:   rec.status,
				})
			}
		}()
		gw.githubProxy.ServeHTTP(rec, r)
		return
	}

	gw.githubProxy.ServeHTTP(w, r)
}

func (gw *gateway) handleGitHubAPI(w http.ResponseWriter, r *http.Request) {
	claims, ok := gw.authenticate(w, r)
	if !ok {
		return
	}

	owner := r.PathValue("owner")
	repo := r.PathValue("repo")
	rest := r.PathValue("path")
	if !validSingleSegment(owner) || !validSingleSegment(repo) || !validRelativePath(rest) {
		http.Error(w, "invalid repository path", http.StatusBadRequest)
		return
	}
	targetRepo := owner + "/" + repo
	isWrite := r.Method != http.MethodGet && r.Method != http.MethodHead
	if claims.Repo != targetRepo {
		if isWrite {
			gw.logGitHubAPIWriteAudit(githubAPIWriteAudit{
				Decision: "deny",
				Reason:   "forbidden_repo",
				Sandbox:  claims.JTI,
				Repo:     targetRepo,
				Method:   r.Method,
				Path:     rest,
				Status:   http.StatusForbidden,
			})
		}
		http.Error(w, "forbidden repository", http.StatusForbidden)
		return
	}
	if !githubAPIAllowed(r.Method, rest) {
		if isWrite {
			gw.logGitHubAPIWriteAudit(githubAPIWriteAudit{
				Decision: "deny",
				Reason:   "forbidden_operation",
				Sandbox:  claims.JTI,
				Repo:     targetRepo,
				Method:   r.Method,
				Path:     rest,
				Status:   http.StatusForbidden,
			})
		}
		http.Error(w, "forbidden github api operation", http.StatusForbidden)
		return
	}

	if isWrite {
		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			gw.logGitHubAPIWriteAudit(githubAPIWriteAudit{
				Decision: "allow",
				Sandbox:  claims.JTI,
				Repo:     targetRepo,
				Method:   r.Method,
				Path:     rest,
				Status:   rec.status,
			})
		}()
		gw.githubAPIProxy.ServeHTTP(rec, r)
		return
	}

	gw.githubAPIProxy.ServeHTTP(w, r)
}

func (gw *gateway) handleModelProxy(provider, routePrefix string, proxy *httputil.ReverseProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := gw.authenticate(w, r); !ok {
			return
		}
		if !modelOperationAllowed(r.Method, r.URL.Path, routePrefix) {
			http.Error(w, "forbidden model operation", http.StatusForbidden)
			return
		}
		if proxy == nil {
			http.Error(w, provider+" model provider is not configured", http.StatusServiceUnavailable)
			return
		}

		proxy.ServeHTTP(w, r)
	}
}

func (gw *gateway) handleDeleteSelf(w http.ResponseWriter, r *http.Request) {
	claims, ok := gw.authenticate(w, r)
	if !ok {
		return
	}
	if gw.sandboxes == nil {
		http.Error(w, "sandbox controller is not configured", http.StatusServiceUnavailable)
		return
	}

	if err := gw.sandboxes.Delete(r.Context(), claims.JTI); err != nil {
		status := http.StatusInternalServerError
		reason := "delete_failed"
		msg := "failed to delete sandbox"
		if apierrors.IsNotFound(err) {
			status = http.StatusNotFound
			reason = "not_found"
			msg = "sandbox not found"
		} else {
			log.Printf("delete sandbox %s failed: %v", claims.JTI, err)
		}
		gw.logSandboxDeleteAudit(sandboxDeleteAudit{
			Decision: "error",
			Reason:   reason,
			Sandbox:  claims.JTI,
			Repo:     claims.Repo,
			Status:   status,
		})
		http.Error(w, msg, status)
		return
	}

	gw.logSandboxDeleteAudit(sandboxDeleteAudit{
		Decision: "allow",
		Sandbox:  claims.JTI,
		Repo:     claims.Repo,
		Status:   http.StatusNoContent,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (gw *gateway) authenticate(w http.ResponseWriter, r *http.Request) (token.SandboxTokenClaims, bool) {
	if gw.sandboxes != nil && !gw.sandboxes.HasSynced() {
		http.Error(w, "gateway not ready", http.StatusServiceUnavailable)
		return token.SandboxTokenClaims{}, false
	}

	rawToken := extractSandboxToken(r)
	if rawToken == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="ada-gateway"`)
		http.Error(w, "missing sandbox token", http.StatusUnauthorized)
		return token.SandboxTokenClaims{}, false
	}

	claims, err := token.VerifySandboxToken(rawToken, gw.signingKey, time.Now())
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="ada-gateway"`)
		http.Error(w, "invalid sandbox token", http.StatusUnauthorized)
		return token.SandboxTokenClaims{}, false
	}

	if gw.sandboxes != nil && (claims.JTI == "" || !gw.sandboxes.IsActive(claims.JTI, claims.Repo)) {
		w.Header().Set("WWW-Authenticate", `Basic realm="ada-gateway"`)
		http.Error(w, "sandbox is not active", http.StatusUnauthorized)
		return token.SandboxTokenClaims{}, false
	}

	return claims, true
}

func extractSandboxToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		if len(auth) >= 7 && strings.EqualFold(auth[:7], "Bearer ") {
			if tok := strings.TrimSpace(auth[7:]); tok != "" {
				return tok
			}
		}
		if _, password, ok := r.BasicAuth(); ok && password != "" {
			return password
		}
	}

	for _, headerName := range []string{"x-api-key", "x-goog-api-key"} {
		if tok := strings.TrimSpace(r.Header.Get(headerName)); tok != "" {
			return tok
		}
	}

	return strings.TrimSpace(r.URL.Query().Get("key"))
}

func gitOperationAllowed(method, rest string) bool {
	switch rest {
	case "info/refs":
		return method == http.MethodGet
	case "git-upload-pack", "git-receive-pack":
		return method == http.MethodPost
	}
	return false
}

func githubAPIAllowed(method, rest string) bool {
	if method == http.MethodGet || method == http.MethodHead {
		return true
	}
	for _, allowed := range allowedGitHubAPIWrites {
		if method != allowed.method {
			continue
		}
		if matched, _ := path.Match(allowed.pathPattern, rest); matched {
			return true
		}
	}
	return false
}

func modelOperationAllowed(method, requestPath, routePrefix string) bool {
	if method != http.MethodGet && method != http.MethodPost {
		return false
	}
	upstreamPath := stripRoutePrefix(requestPath, routePrefix)
	if !validRelativePath(strings.TrimPrefix(upstreamPath, "/")) {
		return false
	}
	return strings.HasPrefix(upstreamPath, "/v1/") || strings.HasPrefix(upstreamPath, "/v1beta/")
}

func stripRoutePrefix(requestPath, routePrefix string) string {
	if routePrefix == "" {
		return requestPath
	}
	if rest, ok := strings.CutPrefix(requestPath, routePrefix+"/"); ok {
		return "/" + rest
	}
	return requestPath
}

func readReceivePackCommands(body io.Reader) ([]byte, []receivePackUpdate, error) {
	var consumed bytes.Buffer
	var updates []receivePackUpdate
	for {
		var lenHex [4]byte
		if _, err := io.ReadFull(body, lenHex[:]); err != nil {
			return nil, nil, fmt.Errorf("%w: truncated pkt-line length", errMalformedReceivePack)
		}
		consumed.Write(lenHex[:])

		pktLen, err := strconv.ParseUint(string(lenHex[:]), 16, 16)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid pkt-line length", errMalformedReceivePack)
		}
		if pktLen == 0 {
			return consumed.Bytes(), updates, nil
		}
		if pktLen < 4 {
			return nil, nil, fmt.Errorf("%w: invalid pkt-line length", errMalformedReceivePack)
		}
		if consumed.Len()+int(pktLen) > maxReceivePackCommandBytes {
			return nil, nil, fmt.Errorf("%w: command section too large", errMalformedReceivePack)
		}

		payload := make([]byte, pktLen-4)
		if _, err := io.ReadFull(body, payload); err != nil {
			return nil, nil, fmt.Errorf("%w: truncated pkt-line payload", errMalformedReceivePack)
		}
		consumed.Write(payload)

		command, _, _ := bytes.Cut(payload, []byte{0})
		if !utf8.Valid(command) {
			return nil, nil, fmt.Errorf("%w: non-utf8 command", errMalformedReceivePack)
		}
		fields := strings.Fields(string(command))
		if len(fields) < 3 {
			return nil, nil, fmt.Errorf("%w: expected <old> <new> <ref>", errMalformedReceivePack)
		}
		updates = append(updates, receivePackUpdate{
			OldOID: fields[0],
			NewOID: fields[1],
			Ref:    fields[2],
		})
	}
}

func newReverseProxy(rewrite func(*httputil.ProxyRequest)) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite:       rewrite,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("upstream proxy error (%s %s): %v", r.Method, r.URL.Path, err)
			http.Error(w, "upstream gateway error", http.StatusBadGateway)
		},
	}
}

func setTargetPath(pr *httputil.ProxyRequest, upstream *url.URL, targetPath string) {
	pr.SetURL(upstream)
	pr.Out.URL.Path = joinPaths(upstream.Path, targetPath)
	pr.Out.URL.RawPath = ""
	pr.Out.URL.RawQuery = pr.In.URL.RawQuery
	if query := pr.Out.URL.Query(); query.Has("key") {
		query.Del("key")
		pr.Out.URL.RawQuery = query.Encode()
	}
}

func parseUpstreamURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("url %q must use http or https scheme with host", raw)
	}
	return u, nil
}

func joinPaths(base, rel string) string {
	if base == "" {
		return rel
	}
	if rel == "" {
		return base
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(rel, "/")
}

func stripClientAuthHeaders(h http.Header) {
	h.Del("Authorization")
	h.Del("Cookie")
	h.Del("X-Api-Key")
	h.Del("X-Goog-Api-Key")
}

func validSingleSegment(segment string) bool {
	return segment != "" && segment != "." && segment != ".." && !strings.ContainsAny(segment, "/\\")
}

func validRelativePath(rel string) bool {
	if strings.Contains(rel, "\\") {
		return false
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
