package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMintAndVerifyRoundTrip(t *testing.T) {
	now := time.Unix(1700000000, 0)
	signingKey := []byte("test-signing-key")
	want := SandboxTokenClaims{
		JTI:       "sandbox-123",
		Repo:      "leomcl/better-branch",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	}

	raw, err := MintSandboxToken(want, signingKey)
	if err != nil {
		t.Fatalf("MintSandboxToken failed: %v", err)
	}

	got, err := VerifySandboxToken(raw, signingKey, now)
	if err != nil {
		t.Fatalf("VerifySandboxToken failed: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("claims mismatch: got %+v, want %+v", got, want)
	}
}

func TestVerifyRejectsWrongSigningKey(t *testing.T) {
	now := time.Unix(1700000000, 0)
	claims := SandboxTokenClaims{
		JTI:       "sandbox-123",
		Repo:      "leomcl/better-branch",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	}

	raw, err := MintSandboxToken(claims, []byte("key-a"))
	if err != nil {
		t.Fatalf("MintSandboxToken failed: %v", err)
	}

	if _, err := VerifySandboxToken(raw, []byte("key-b"), now); err == nil {
		t.Fatal("expected error for wrong signing key")
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	now := time.Unix(1700000000, 0)
	claims := SandboxTokenClaims{
		JTI:       "sandbox-expired",
		Repo:      "leomcl/better-branch",
		IssuedAt:  now.Add(-10 * time.Minute).Unix(),
		ExpiresAt: now.Add(-time.Minute).Unix(),
	}
	signingKey := []byte("test-signing-key")

	raw, err := MintSandboxToken(claims, signingKey)
	if err != nil {
		t.Fatalf("MintSandboxToken failed: %v", err)
	}

	if _, err := VerifySandboxToken(raw, signingKey, now); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyRejectsTamperedPayloadAndUnsupportedAlg(t *testing.T) {
	now := time.Unix(1700000000, 0)
	signingKey := []byte("test-signing-key")
	claims := SandboxTokenClaims{
		JTI:       "sandbox-123",
		Repo:      "leomcl/better-branch",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	}

	raw, err := MintSandboxToken(claims, signingKey)
	if err != nil {
		t.Fatalf("MintSandboxToken failed: %v", err)
	}

	parts := strings.Split(raw, ".")
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"sandbox-123","repo":"leomcl/other-repo","iat":1700000000,"exp":1700003600}`))
	tampered := parts[0] + "." + tamperedPayload + "." + parts[2]
	if _, err := VerifySandboxToken(tampered, signingKey, now); err == nil {
		t.Fatal("expected error for tampered payload")
	}

	badHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	signingInput := badHeader + "." + parts[1]
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(signingInput))
	badAlgToken := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if _, err := VerifySandboxToken(badAlgToken, signingKey, now); err == nil {
		t.Fatal("expected error for unsupported alg")
	}
}

func TestParseSigningKeyTrimsWhitespace(t *testing.T) {
	now := time.Unix(1700000000, 0)
	keyWithNewline := []byte("  cluster-signing-secret-key\n")
	trimmedKey := []byte("cluster-signing-secret-key")

	parsed, err := ParseSigningKey(keyWithNewline)
	if err != nil {
		t.Fatalf("ParseSigningKey: %v", err)
	}
	if string(parsed) != string(trimmedKey) {
		t.Fatalf("ParseSigningKey: got %q, want %q", parsed, trimmedKey)
	}

	for _, empty := range [][]byte{nil, []byte(""), []byte("  \n\t ")} {
		if _, err := ParseSigningKey(empty); err == nil {
			t.Fatalf("expected error for empty/whitespace key %q", empty)
		}
	}

	claims := SandboxTokenClaims{
		JTI:       "sandbox-123",
		Repo:      "leomcl/ada",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	}
	raw, err := MintSandboxToken(claims, parsed)
	if err != nil {
		t.Fatalf("MintSandboxToken: %v", err)
	}
	if _, err := VerifySandboxToken(raw, trimmedKey, now); err != nil {
		t.Fatalf("VerifySandboxToken with trimmed key failed: %v", err)
	}
}
