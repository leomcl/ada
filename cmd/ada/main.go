package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/leomcl/ada/internal/sandbox"
	"github.com/leomcl/ada/internal/token"
)

const (
	tokenUsage = "usage: ada token <owner/repo> [--ttl 12h] [--jti <sandbox-name>]  (key from ADA_SIGNING_KEY)"
	upUsage    = "usage: ada up [owner/repo] [--config ada.yaml] [--access rex|tty|headless] [--harness opencode|claude|agy|\"\"] [--image <image>] [--namespace <ns>] [--system-namespace <ns>] [--signing-key-secret <name>] [--gateway <url>] [--runtime-class <name>] [--ttl 12h] [--tailscale-authkey <key>] [--wait=true] [--no-connect]"
	lsUsage    = "usage: ada ls [--namespace <ns>]"
	downUsage  = "usage: ada down <name> [--namespace <ns>]"
	sshUsage   = "usage: ada ssh <name> [--namespace <ns>] [-- command...]  (runs kubectl exec)"
	rexUsage   = "usage: ada rex <name> [--namespace <ns>]"
)

type usageError struct{ msg string }

func (e usageError) Error() string {
	return e.msg
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) < 2 {
		printRootUsage(os.Stderr)
		os.Exit(2)
	}

	subcmd := os.Args[1]
	if subcmd == "-h" || subcmd == "--help" || subcmd == "help" {
		printRootUsage(os.Stdout)
		return
	}

	var err error
	switch subcmd {
	case "up":
		err = runUp(ctx, os.Args[2:])
	case "ls":
		err = runList(ctx, os.Args[2:])
	case "down":
		err = runDown(ctx, os.Args[2:])
	case "ssh":
		err = runSSH(ctx, os.Args[2:])
	case "rex":
		err = runRex(ctx, os.Args[2:])
	case "token":
		err = runToken(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", subcmd)
		printRootUsage(os.Stderr)
		os.Exit(2)
	}

	if err != nil {
		var uerr usageError
		if errors.As(err, &uerr) {
			if uerr.msg != "" {
				fmt.Fprintln(os.Stderr, uerr.msg)
			}
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "ada %s: %v\n", subcmd, err)
		os.Exit(1)
	}
}

func printRootUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: ada <command> [args]")
	fmt.Fprintln(w, "commands: up, ls, down, ssh, rex, token")
}

func runUp(ctx context.Context, args []string) error {
	cfg, err := loadConfig(findConfigFlag(args))
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	_ = fs.String("config", "", "path to ada.yaml")
	fs.StringVar(&cfg.Access, "access", cfg.Access, "access mode: rex, tty, or headless")
	fs.StringVar(&cfg.Harness, "harness", cfg.Harness, "coding harness: opencode, claude, agy, or empty")
	fs.StringVar(&cfg.Image, "image", cfg.Image, "sandbox container image")
	fs.StringVar(&cfg.Namespace, "namespace", cfg.Namespace, "workload namespace")
	fs.StringVar(&cfg.SystemNamespace, "system-namespace", cfg.SystemNamespace, "system namespace holding signing key secret")
	fs.StringVar(&cfg.SigningKeySecret, "signing-key-secret", cfg.SigningKeySecret, "secret name holding signing key")
	fs.StringVar(&cfg.GatewayURL, "gateway", cfg.GatewayURL, "ada-gateway base URL")
	fs.StringVar(&cfg.RuntimeClass, "runtime-class", cfg.RuntimeClass, "Kubernetes RuntimeClassName (empty for none)")
	fs.DurationVar(&cfg.TTL.Duration, "ttl", cfg.TTL.Duration, "sandbox and token lifetime")
	fs.StringVar(&cfg.TailscaleAuthKey, "tailscale-authkey", cfg.TailscaleAuthKey, "Tailscale auth key")
	waitReady := fs.Bool("wait", true, "wait for sandbox readiness")
	noConnect := fs.Bool("no-connect", false, "do not attach after creation")

	pos, err := parseFlags(fs, args, upUsage)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usageError{upUsage}
	}
	if len(pos) == 1 {
		cfg.Repo = pos[0]
	}
	if cfg.Repo == "" {
		return usageError{"ada up: repo is required via argument or ada.yaml\n" + upUsage}
	}

	mgr, err := sandbox.NewClusterManager()
	if err != nil {
		return err
	}

	sb, err := mgr.Create(ctx, cfg)
	if err != nil {
		return err
	}
	fmt.Printf("created sandbox %s in %s (repo=%s access=%s)\n", sb.Name, sb.Namespace, cfg.Repo, cfg.Access)

	if !*waitReady {
		return nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	readySandbox, err := mgr.WaitUntilReady(waitCtx, sb.Namespace, sb.Name, time.Second)
	cancel()
	if err != nil {
		return err
	}
	fmt.Printf("sandbox %s is ready\n", readySandbox.Name)

	if *noConnect {
		return nil
	}

	switch cfg.Access {
	case "tty":
		return connectTTY(ctx, readySandbox.Namespace, sandbox.PodName(readySandbox), cfg.Harness)
	case "rex":
		return connectRex(ctx, readySandbox.Namespace, sandbox.PodName(readySandbox), readySandbox.Name, cfg.Harness)
	default:
		return nil
	}
}

func runList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	namespace := fs.String("namespace", sandbox.DefaultWorkloadNamespace, "workload namespace")
	pos, err := parseFlags(fs, args, lsUsage)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageError{lsUsage}
	}

	mgr, err := sandbox.NewClusterManager()
	if err != nil {
		return err
	}

	items, err := mgr.List(ctx, *namespace)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tREPO\tACCESS\tHARNESS\tREADY\tAGE")
	now := time.Now()
	for _, item := range items {
		harness := item.Harness
		if harness == "" {
			harness = "-"
		}
		ready := item.Ready
		if item.Ready == "False" && item.Reason != "" {
			ready = fmt.Sprintf("False (%s)", item.Reason)
		}
		age := "-"
		if !item.CreatedAt.IsZero() {
			age = formatAge(now.Sub(item.CreatedAt))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", item.Name, item.Repo, item.Access, harness, ready, age)
	}
	_ = tw.Flush()
	return nil
}

func runDown(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	namespace := fs.String("namespace", sandbox.DefaultWorkloadNamespace, "workload namespace")
	pos, err := parseFlags(fs, args, downUsage)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{downUsage}
	}
	nameArg := pos[0]

	mgr, err := sandbox.NewClusterManager()
	if err != nil {
		return err
	}
	if err := mgr.Delete(ctx, *namespace, nameArg); err != nil {
		return err
	}
	fmt.Printf("deleted sandbox %s\n", nameArg)
	return nil
}

func runSSH(ctx context.Context, args []string) error {
	beforeDash, command := splitDoubleDash(args)
	fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
	namespace := fs.String("namespace", sandbox.DefaultWorkloadNamespace, "workload namespace")
	pos, err := parseFlags(fs, beforeDash, sshUsage)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{sshUsage}
	}
	nameArg := pos[0]

	mgr, err := sandbox.NewClusterManager()
	if err != nil {
		return err
	}
	sb, err := mgr.Get(ctx, *namespace, nameArg)
	if err != nil {
		return err
	}
	return connectTTY(ctx, sb.Namespace, sandbox.PodName(sb), sb.Annotations[sandbox.HarnessAnnotation], command...)
}

func runRex(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rex", flag.ContinueOnError)
	namespace := fs.String("namespace", sandbox.DefaultWorkloadNamespace, "workload namespace")
	pos, err := parseFlags(fs, args, rexUsage)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{rexUsage}
	}
	nameArg := pos[0]

	mgr, err := sandbox.NewClusterManager()
	if err != nil {
		return err
	}
	sb, err := mgr.Get(ctx, *namespace, nameArg)
	if err != nil {
		return err
	}
	return connectRex(ctx, sb.Namespace, sandbox.PodName(sb), sb.Name, sb.Annotations[sandbox.HarnessAnnotation])
}

func runToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	jti := fs.String("jti", "", "sandbox name the token is bound to (default: random)")
	ttl := fs.Duration("ttl", sandbox.DefaultTokenTTL, "token lifetime")
	pos, err := parseFlags(fs, args, tokenUsage)
	if err != nil {
		return err
	}
	if len(pos) != 1 || !sandbox.ValidRepo(pos[0]) {
		return usageError{tokenUsage}
	}
	repo := pos[0]

	signingKey, err := token.ParseSigningKey([]byte(os.Getenv("ADA_SIGNING_KEY")))
	if err != nil {
		return fmt.Errorf("ADA_SIGNING_KEY: %w", err)
	}

	tokenID := *jti
	if tokenID == "" {
		tokenID, err = sandbox.GenerateSandboxName("local")
		if err != nil {
			return err
		}
	}

	now := time.Now()
	tok, err := token.MintSandboxToken(token.SandboxTokenClaims{
		JTI:       tokenID,
		Repo:      repo,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(*ttl).Unix(),
	}, signingKey)
	if err != nil {
		return fmt.Errorf("mint token: %w", err)
	}
	fmt.Println(tok)
	return nil
}

func parseFlags(fs *flag.FlagSet, args []string, usage string) ([]string, error) {
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), usage)
		fs.PrintDefaults()
	}

	var pos []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return nil, usageError{}
		}
		if fs.NArg() == 0 {
			break
		}
		consumed := len(rest) - fs.NArg()
		if consumed > 0 && rest[consumed-1] == "--" {
			pos = append(pos, fs.Args()...)
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	return pos, nil
}

func splitDoubleDash(args []string) ([]string, []string) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func formatAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
