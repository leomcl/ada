package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/leomcl/ada/internal/token"
)

const tokenUsage = "usage: ada token <owner/repo> [--ttl 12h] [--jti <sandbox-name>]  (key from ADA_SIGNING_KEY)"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ada <command> [args]")
		fmt.Fprintln(os.Stderr, "commands: token")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "token":
		runToken(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func runToken(args []string) {
	if len(args) < 1 || !validRepo(args[0]) {
		fmt.Fprintln(os.Stderr, tokenUsage)
		os.Exit(2)
	}
	repo := args[0]

	fs := flag.NewFlagSet("token", flag.ExitOnError)
	jti := fs.String("jti", "", "sandbox name the token is bound to (default: random)")
	ttl := fs.Duration("ttl", 12*time.Hour, "token lifetime")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, tokenUsage)
		os.Exit(2)
	}

	signingKey := os.Getenv("ADA_SIGNING_KEY")
	if signingKey == "" {
		fmt.Fprintln(os.Stderr, "ADA_SIGNING_KEY must be set")
		os.Exit(2)
	}

	tokenID := *jti
	if tokenID == "" {
		tokenID = "local-" + randomSuffix()
	}

	now := time.Now()
	tok, err := token.MintSandboxToken(token.SandboxTokenClaims{
		JTI:       tokenID,
		Repo:      repo,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(*ttl).Unix(),
	}, []byte(signingKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint token: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(tok)
}

func validRepo(repo string) bool {
	owner, name, ok := strings.Cut(repo, "/")
	return ok && owner != "" && name != "" && !strings.Contains(name, "/")
}

func randomSuffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
