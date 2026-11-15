package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type SandboxTokenClaims struct {
	JTI       string `json:"jti"`
	Repo      string `json:"repo"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func MintSandboxToken(claims SandboxTokenClaims, signingKey []byte) (string, error) {
	if len(signingKey) == 0 {
		return "", errors.New("signing key must not be empty")
	}

	headerBytes, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) +
		"." +
		base64.RawURLEncoding.EncodeToString(claimsBytes)
	sig := signHS256(signingInput, signingKey)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifySandboxToken(rawToken string, signingKey []byte, now time.Time) (SandboxTokenClaims, error) {
	if len(signingKey) == 0 {
		return SandboxTokenClaims{}, errors.New("signing key must not be empty")
	}

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return SandboxTokenClaims{}, errors.New("invalid jwt format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return SandboxTokenClaims{}, fmt.Errorf("decode header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return SandboxTokenClaims{}, fmt.Errorf("unmarshal header: %w", err)
	}
	if header.Alg != "HS256" {
		return SandboxTokenClaims{}, fmt.Errorf("unsupported jwt alg: %q", header.Alg)
	}

	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return SandboxTokenClaims{}, fmt.Errorf("decode signature: %w", err)
	}
	expectedSig := signHS256(parts[0]+"."+parts[1], signingKey)
	if !hmac.Equal(gotSig, expectedSig) {
		return SandboxTokenClaims{}, errors.New("invalid jwt signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return SandboxTokenClaims{}, fmt.Errorf("decode payload: %w", err)
	}
	var claims SandboxTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return SandboxTokenClaims{}, fmt.Errorf("unmarshal claims: %w", err)
	}

	if now.Unix() >= claims.ExpiresAt {
		return SandboxTokenClaims{}, errors.New("token expired")
	}

	return claims, nil
}

func signHS256(signingInput string, signingKey []byte) []byte {
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}
