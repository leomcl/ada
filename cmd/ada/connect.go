package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

func defaultShellCommand(harness string, command ...string) []string {
	if len(command) > 0 {
		return command
	}
	if harness != "" {
		return []string{harness}
	}
	return []string{"bash"}
}

func kubectlExecArgs(namespace, podName, harness string, tty bool, command ...string) []string {
	execFlag := "-i"
	if tty {
		execFlag = "-it"
	}
	args := []string{"exec", execFlag}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	args = append(args, podName, "--")
	return append(args, defaultShellCommand(harness, command...)...)
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func connectTTY(ctx context.Context, namespace, podName, harness string, command ...string) error {
	args := kubectlExecArgs(namespace, podName, harness, isTerminal(os.Stdin), command...)
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func connectRex(ctx context.Context, namespace, podName, sandboxName, harness string) error {
	rexBin, err := exec.LookPath("rex")
	if err != nil {
		fmt.Fprintln(os.Stderr, "rex not found in PATH; falling back to kubectl exec")
		return connectTTY(ctx, namespace, podName, harness)
	}

	var (
		listOut []byte
		lastErr error
	)
	pollErr := wait.PollUntilContextTimeout(ctx, time.Second, 15*time.Second, true, func(ctx context.Context) (bool, error) {
		listCmd := exec.CommandContext(ctx, rexBin, "--autostart=false", "--timeout=3s", "-S", sandboxName, "ls", "--json")
		out, err := listCmd.Output()
		if err != nil {
			lastErr = err
			return false, nil
		}
		listOut = out
		return true, nil
	})
	if pollErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fmt.Fprintf(os.Stderr, "rex server on %s not reachable (%v); falling back to kubectl exec\n", sandboxName, lastErr)
		return connectTTY(ctx, namespace, podName, harness)
	}

	if rexSessionsEmpty(listOut) {
		newArgs := []string{"--autostart=false", "-S", sandboxName, "new", "ada", "-c", "/workspace", "--"}
		newArgs = append(newArgs, defaultShellCommand(harness)...)
		newCmd := exec.CommandContext(ctx, rexBin, newArgs...)
		newCmd.Stdout = os.Stdout
		newCmd.Stderr = os.Stderr
		if err := newCmd.Run(); err != nil {
			return fmt.Errorf("create rex session on %s: %w", sandboxName, err)
		}
	}
	fmt.Printf("rex ready on %s (run: rex -S %s ls)\n", sandboxName, sandboxName)
	return nil
}

func rexSessionsEmpty(raw []byte) bool {
	var resp struct {
		Sessions []any `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false
	}
	return resp.Sessions != nil && len(resp.Sessions) == 0
}
