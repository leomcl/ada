package gateway

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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

var modelRoutePrefixes = []string{"/anthropic", "/google"}

type Config struct {
	SigningKey       []byte
	GitHubPAT        string
	GitHubBaseURL    string
	GitHubAPIBaseURL string
	CLIProxyBaseURL  string
	CLIProxyAPIKey   string
}

type gateway struct {
	cfg            Config
	githubProxy    *httputil.ReverseProxy
	githubAPIProxy *httputil.ReverseProxy
	cliproxyProxy  *httputil.ReverseProxy
}

func NewHandler(cfg Config) (http.Handler, error) {
	signingKey, err := token.ParseSigningKey(cfg.SigningKey)
	if err != nil {
		return nil, err
	}
	cfg.SigningKey = signingKey
	cfg.GitHubPAT = strings.TrimSpace(cfg.GitHubPAT)
	cfg.CLIProxyAPIKey = strings.TrimSpace(cfg.CLIProxyAPIKey)

	githubURL, err := parseUpstreamURL(cfg.GitHubBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid GitHubBaseURL: %w", err)
	}
	githubAPIURL, err := parseUpstreamURL(cfg.GitHubAPIBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid GitHubAPIBaseURL: %w", err)
	}
	cliproxyURL, err := parseUpstreamURL(cfg.CLIProxyBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid CLIProxyBaseURL: %w", err)
	}

	gitBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+cfg.GitHubPAT))

	gw := &gateway{
		cfg: cfg,
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
			pr.Out.Header.Set("Authorization", "Bearer "+cfg.GitHubPAT)
			if pr.Out.Header.Get("User-Agent") == "" {
				pr.Out.Header.Set("User-Agent", "ada-gateway")
			}
		}),
		cliproxyProxy: newReverseProxy(func(pr *httputil.ProxyRequest) {
			setTargetPath(pr, cliproxyURL, modelUpstreamPath(pr.In.URL.Path))
			stripClientAuthHeaders(pr.Out.Header)
			if cfg.CLIProxyAPIKey != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+cfg.CLIProxyAPIKey)
			}
		}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/github/{owner}/{repo}/{path...}", gw.handleGitHubGit)
	mux.HandleFunc("/github-api/repos/{owner}/{repo}", gw.handleGitHubAPI)
	mux.HandleFunc("/github-api/repos/{owner}/{repo}/{path...}", gw.handleGitHubAPI)
	mux.HandleFunc("/v1/{path...}", gw.handleModelProxy)
	for _, prefix := range modelRoutePrefixes {
		mux.HandleFunc(prefix+"/{path...}", gw.handleModelProxy)
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
	if claims.Repo != owner+"/"+strings.TrimSuffix(repo, ".git") {
		http.Error(w, "forbidden repository", http.StatusForbidden)
		return
	}
	if !gitOperationAllowed(r.Method, rest) {
		http.Error(w, "forbidden git operation", http.StatusForbidden)
		return
	}

	if rest == "git-receive-pack" {
		commands, err := readReceivePackCommands(r.Body)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errProtectedRef) {
				status = http.StatusForbidden
			}
			http.Error(w, err.Error(), status)
			return
		}
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(commands), r.Body), r.Body}
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
	if claims.Repo != owner+"/"+repo {
		http.Error(w, "forbidden repository", http.StatusForbidden)
		return
	}
	if !githubAPIAllowed(r.Method, rest) {
		http.Error(w, "forbidden github api operation", http.StatusForbidden)
		return
	}

	gw.githubAPIProxy.ServeHTTP(w, r)
}

func (gw *gateway) handleModelProxy(w http.ResponseWriter, r *http.Request) {
	if _, ok := gw.authenticate(w, r); !ok {
		return
	}

	gw.cliproxyProxy.ServeHTTP(w, r)
}

func (gw *gateway) authenticate(w http.ResponseWriter, r *http.Request) (token.SandboxTokenClaims, bool) {
	rawToken := extractSandboxToken(r)
	if rawToken == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="ada-gateway"`)
		http.Error(w, "missing sandbox token", http.StatusUnauthorized)
		return token.SandboxTokenClaims{}, false
	}

	claims, err := token.VerifySandboxToken(rawToken, gw.cfg.SigningKey, time.Now())
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="ada-gateway"`)
		http.Error(w, "invalid sandbox token", http.StatusUnauthorized)
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

func modelUpstreamPath(requestPath string) string {
	for _, prefix := range modelRoutePrefixes {
		if rest, ok := strings.CutPrefix(requestPath, prefix+"/"); ok {
			return "/" + rest
		}
	}
	return requestPath
}

func readReceivePackCommands(body io.Reader) ([]byte, error) {
	var consumed bytes.Buffer
	for {
		var lenHex [4]byte
		if _, err := io.ReadFull(body, lenHex[:]); err != nil {
			return nil, fmt.Errorf("%w: truncated pkt-line length", errMalformedReceivePack)
		}
		consumed.Write(lenHex[:])

		pktLen, err := strconv.ParseUint(string(lenHex[:]), 16, 16)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid pkt-line length", errMalformedReceivePack)
		}
		if pktLen == 0 {
			return consumed.Bytes(), nil
		}
		if pktLen < 4 {
			return nil, fmt.Errorf("%w: invalid pkt-line length", errMalformedReceivePack)
		}
		if consumed.Len()+int(pktLen) > maxReceivePackCommandBytes {
			return nil, fmt.Errorf("%w: command section too large", errMalformedReceivePack)
		}

		payload := make([]byte, pktLen-4)
		if _, err := io.ReadFull(body, payload); err != nil {
			return nil, fmt.Errorf("%w: truncated pkt-line payload", errMalformedReceivePack)
		}
		consumed.Write(payload)

		command, _, _ := bytes.Cut(payload, []byte{0})
		if !utf8.Valid(command) {
			return nil, fmt.Errorf("%w: non-utf8 command", errMalformedReceivePack)
		}
		fields := strings.Fields(string(command))
		if len(fields) < 3 {
			return nil, fmt.Errorf("%w: expected <old> <new> <ref>", errMalformedReceivePack)
		}
		if refName := fields[2]; protectedRefs[refName] {
			return nil, fmt.Errorf("%w: %s", errProtectedRef, refName)
		}
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
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("url %q must include scheme and host", raw)
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
	for _, seg := range strings.Split(rel, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
