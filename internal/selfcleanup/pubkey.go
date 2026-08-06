package selfcleanup

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
)

// The Ferralon revoke-signing PUBLIC key is baked into the pinned Assay scanner
// release at build time, exactly like the scanner-sha256 pin, by the release
// publish pipeline. These are string vars — NOT consts —
// so the linker can substitute them with `-ldflags "-X ...=<value>"` at cut time:
//
//	go build -ldflags "\
//	  -X github.com/ferralon-ai/ferralon-assay/internal/selfcleanup.bakedRevokePubKey=<base64-raw-32-byte-key> \
//	  -X github.com/ferralon-ai/ferralon-assay/internal/selfcleanup.bakedRevokeKeyID=<key-id>" ...
//
// A build with no key baked in (the OSS default `go build`) leaves both empty; the
// revoke check then has no trusted key and every 410 is treated as transient (never
// actuates) — fail-safe. Only a properly-cut Assay release carries a key.
var (
	bakedRevokePubKey string // base64 of the raw 32-byte Ed25519 public key
	bakedRevokeKeyID  string // rotation key id
)

// Environment overrides for hermetic tests and dev/integration runs. When set they
// take precedence over the baked-in values, letting a test drive a known keypair
// without relinking. The names match dispatch 03's public-key handoff contract
// (FERRALON_REVOKE_PUBLIC_KEY = standard-base64 of the raw 32-byte Ed25519 public
// key; FERRALON_REVOKE_KEY_ID = the rotation key id).
const (
	envRevokePubKey = "FERRALON_REVOKE_PUBLIC_KEY"
	envRevokeKeyID  = "FERRALON_REVOKE_KEY_ID"
)

// TrustedKey resolves the public key + key id the scanner trusts for revoke
// signatures: the env override if present, else the build-time baked value. It
// returns (nil, "", nil) when no key is configured — a legitimate state (OSS build)
// in which the caller must treat every 410 as transient and never actuate.
func TrustedKey() (ed25519.PublicKey, string, error) {
	b64 := firstNonEmpty(os.Getenv(envRevokePubKey), bakedRevokePubKey)
	keyID := firstNonEmpty(os.Getenv(envRevokeKeyID), bakedRevokeKeyID)
	if b64 == "" {
		return nil, "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, "", fmt.Errorf("selfcleanup: revoke public key is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("selfcleanup: revoke public key must be %d raw bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), keyID, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
