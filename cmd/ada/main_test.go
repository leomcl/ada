package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/leomcl/ada/internal/sandbox"
)

func TestLoadConfigAndPrecedence(t *testing.T) {
	dir := t.TempDir()
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })
	t.Setenv("TS_AUTHKEY", "")
	t.Setenv("ADA_CONFIG", "")

	missingDefault, err := loadConfig()
	if err != nil {
		t.Fatalf("expected missing default ada.yaml to succeed, got: %v", err)
	}
	if !reflect.DeepEqual(missingDefault, sandbox.Defaults()) {
		t.Fatalf("expected Defaults(), got %+v", missingDefault)
	}

	t.Setenv("ADA_CONFIG", filepath.Join(dir, "env-missing.yaml"))
	if _, err := loadConfig(); err == nil {
		t.Fatal("expected error when ADA_CONFIG points to missing file")
	}
	t.Setenv("ADA_CONFIG", "")

	cfgPath := filepath.Join(dir, "ada.yaml")
	yamlContent := `repo: leomcl/ada
access: rex
harness: claude
image: ghcr.io/leomcl/ada-base:v1
namespace: team-sandboxes
gatewayURL: http://custom-gw:8080/
runtimeClass: kata
cpu: "4"
memory: 8Gi
ephemeralStorage: 20Gi
spot: true
ttl: 6h
tailscaleAuthKey: ignored-from-file
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Setenv("TS_AUTHKEY", "tskey-from-env")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Repo != "leomcl/ada" || cfg.Access != "rex" || cfg.Harness != "claude" ||
		cfg.Image != "ghcr.io/leomcl/ada-base:v1" || cfg.Namespace != "team-sandboxes" ||
		cfg.RuntimeClass != "kata" || cfg.CPU != "4" || cfg.Memory != "8Gi" ||
		cfg.EphemeralStorage != "20Gi" || !cfg.Spot || cfg.TTL.Duration != 6*time.Hour ||
		cfg.TailscaleAuthKey != "" {
		t.Fatalf("unexpected loaded config: %+v", cfg)
	}

	// newUpFlags picks up TS_AUTHKEY and lets CLI flags override YAML and env (including empty values).
	fs, _ := newUpFlags(&cfg)
	if cfg.TailscaleAuthKey != "tskey-from-env" {
		t.Fatalf("TailscaleAuthKey env default: got %q, want tskey-from-env", cfg.TailscaleAuthKey)
	}

	if _, err := parseFlags(fs, []string{"--access", "tty", "--harness", "", "--runtime-class", "", "--cpu", "1", "--memory", "2Gi", "--ephemeral-storage", "5Gi", "--spot=false", "--ttl", "2h", "--tailscale-authkey", "tskey-from-flag"}, upUsage); err != nil {
		t.Fatalf("parseFlags: %v", err)
	}

	if cfg.Access != "tty" {
		t.Fatalf("Access override: got %q, want tty", cfg.Access)
	}
	if cfg.Harness != "" {
		t.Fatalf("Harness empty override: got %q, want empty", cfg.Harness)
	}
	if cfg.RuntimeClass != "" {
		t.Fatalf("RuntimeClass empty override: got %q, want empty", cfg.RuntimeClass)
	}
	if cfg.CPU != "1" || cfg.Memory != "2Gi" || cfg.EphemeralStorage != "5Gi" || cfg.Spot {
		t.Fatalf("resource/spot override failed: %+v", cfg)
	}
	if cfg.TTL.Duration != 2*time.Hour {
		t.Fatalf("TTL override: got %s, want 2h", cfg.TTL.Duration)
	}
	if cfg.TailscaleAuthKey != "tskey-from-flag" {
		t.Fatalf("TailscaleAuthKey override: got %q, want tskey-from-flag", cfg.TailscaleAuthKey)
	}
}

func TestParseFlags(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantNS  string
		wantPos []string
	}{
		{
			name:    "positional before flags",
			args:    []string{"my-sb", "--namespace", "ns1"},
			wantNS:  "ns1",
			wantPos: []string{"my-sb"},
		},
		{
			name:    "flags before positional",
			args:    []string{"--namespace", "ns2", "my-sb"},
			wantNS:  "ns2",
			wantPos: []string{"my-sb"},
		},
		{
			name:    "positional between flags",
			args:    []string{"--namespace=ns3", "a", "b"},
			wantNS:  "ns3",
			wantPos: []string{"a", "b"},
		},
		{
			name:    "double dash stops flag parsing",
			args:    []string{"--namespace", "ns4", "--", "--not-a-flag"},
			wantNS:  "ns4",
			wantPos: []string{"--not-a-flag"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			ns := fs.String("namespace", "default", "")
			pos, err := parseFlags(fs, tc.args, "usage")
			if err != nil {
				t.Fatalf("parseFlags: %v", err)
			}
			if *ns != tc.wantNS {
				t.Fatalf("namespace: got %q, want %q", *ns, tc.wantNS)
			}
			if !reflect.DeepEqual(pos, tc.wantPos) {
				t.Fatalf("pos: got %v, want %v", pos, tc.wantPos)
			}
		})
	}
}

func TestConnectHelpers(t *testing.T) {
	gotDefault := kubectlExecArgs("ns1", "pod1", "", true)
	if strings.Join(gotDefault, " ") != "exec -it -n ns1 pod1 -- bash" {
		t.Fatalf("unexpected default args: %v", gotDefault)
	}

	gotHarness := kubectlExecArgs("ns1", "pod1", "claude", true)
	if strings.Join(gotHarness, " ") != "exec -it -n ns1 pod1 -- claude" {
		t.Fatalf("unexpected harness args: %v", gotHarness)
	}

	gotCustomTTY := kubectlExecArgs("ns1", "pod1", "claude", true, "git", "status")
	if strings.Join(gotCustomTTY, " ") != "exec -it -n ns1 pod1 -- git status" {
		t.Fatalf("unexpected custom tty args: %v", gotCustomTTY)
	}

	gotCustomPipe := kubectlExecArgs("ns1", "pod1", "claude", false, "cat")
	if strings.Join(gotCustomPipe, " ") != "exec -i -n ns1 pod1 -- cat" {
		t.Fatalf("unexpected custom pipe args: %v", gotCustomPipe)
	}

	if !rexSessionsEmpty([]byte(`{"sessions":[]}`)) {
		t.Fatal("expected empty sessions payload to return true")
	}
	if rexSessionsEmpty([]byte(`{"sessions":[{"session_id":"s1"}]}`)) {
		t.Fatal("expected non-empty sessions payload to return false")
	}
	if rexSessionsEmpty([]byte(`[]`)) {
		t.Fatal("expected non-object JSON payload to return false")
	}
	if rexSessionsEmpty([]byte(`{}`)) {
		t.Fatal("expected missing sessions field to return false")
	}
}
