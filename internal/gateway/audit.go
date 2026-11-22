package gateway

import "net/http"

type receivePackUpdate struct {
	OldOID string
	NewOID string
	Ref    string
}

type gitPushAudit struct {
	Decision string
	Reason   string
	Sandbox  string
	Repo     string
	Update   receivePackUpdate
	Status   int
}

type githubAPIWriteAudit struct {
	Decision string
	Reason   string
	Sandbox  string
	Repo     string
	Method   string
	Path     string
	Status   int
}

func (gw *gateway) logGitPushAudit(a gitPushAudit) {
	attrs := []any{
		"event", "git_push",
		"decision", a.Decision,
		"sandbox", a.Sandbox,
		"repo", a.Repo,
		"status", a.Status,
	}
	if a.Reason != "" {
		attrs = append(attrs, "reason", a.Reason)
	}
	if a.Update.Ref != "" {
		attrs = append(attrs,
			"ref", a.Update.Ref,
			"old_oid", a.Update.OldOID,
			"new_oid", a.Update.NewOID,
			"create", isZeroOID(a.Update.OldOID),
			"delete", isZeroOID(a.Update.NewOID),
		)
	}
	gw.auditLogger.Info("audit", attrs...)
}

func (gw *gateway) logGitHubAPIWriteAudit(a githubAPIWriteAudit) {
	attrs := []any{
		"event", "github_api_write",
		"decision", a.Decision,
		"sandbox", a.Sandbox,
		"repo", a.Repo,
		"method", a.Method,
		"path", a.Path,
		"status", a.Status,
	}
	if a.Reason != "" {
		attrs = append(attrs, "reason", a.Reason)
	}
	gw.auditLogger.Info("audit", attrs...)
}

func isZeroOID(oid string) bool {
	if len(oid) == 0 {
		return false
	}
	for i := 0; i < len(oid); i++ {
		if oid[i] != '0' {
			return false
		}
	}
	return true
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 && (code < 100 || code >= 200 || code == http.StatusSwitchingProtocols) {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(p)
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
