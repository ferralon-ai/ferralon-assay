package selfcleanup

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func testKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

func TestVerifyValid(t *testing.T) {
	pub, priv := testKeypair(t)
	body, err := Sign(priv, "k1", "acme", "acme/widget", "bm9uY2U=", "2026-07-09T12:00:00Z")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(body, pub, "k1"); err != nil {
		t.Fatalf("valid body must verify, got %v", err)
	}
	// key id is optional on the trusted side (empty accepts any id).
	if err := Verify(body, pub, ""); err != nil {
		t.Fatalf("empty trusted key id must accept, got %v", err)
	}
}

func TestVerifyTamperedContent(t *testing.T) {
	pub, priv := testKeypair(t)
	body, _ := Sign(priv, "k1", "acme", "acme/widget", "bm9uY2U=", "2026-07-09T12:00:00Z")
	// Flip the repo the signature was NOT computed over.
	body.Repo = "acme/other"
	if err := Verify(body, pub, "k1"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered repo must fail with ErrBadSignature, got %v", err)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	_, priv := testKeypair(t)
	otherPub, _ := testKeypair(t)
	body, _ := Sign(priv, "k1", "acme", "acme/widget", "bm9uY2U=", "2026-07-09T12:00:00Z")
	if err := Verify(body, otherPub, "k1"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong key must fail with ErrBadSignature, got %v", err)
	}
}

func TestVerifyKeyIDMismatch(t *testing.T) {
	pub, priv := testKeypair(t)
	body, _ := Sign(priv, "k1", "acme", "acme/widget", "bm9uY2U=", "2026-07-09T12:00:00Z")
	if err := Verify(body, pub, "k2"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("key id mismatch must fail, got %v", err)
	}
}

func TestVerifySchemaMismatch(t *testing.T) {
	pub, priv := testKeypair(t)
	body, _ := Sign(priv, "k1", "acme", "acme/widget", "bm9uY2U=", "2026-07-09T12:00:00Z")
	body.Schema = "ferralon.revoke/v2"
	if err := Verify(body, pub, "k1"); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("schema mismatch must fail with ErrSchemaMismatch, got %v", err)
	}
}

func TestCanonicalMessageShape(t *testing.T) {
	got, err := CanonicalRevokeMessage("acme", "acme/widget", "n", "2026-07-09T12:00:00Z")
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"org":"acme","repo":"acme/widget","nonce":"n","issued_at":"2026-07-09T12:00:00Z"}`
	if string(got) != want {
		t.Fatalf("canonical bytes:\n got %s\nwant %s", got, want)
	}
}

// TestCanonicalHTMLEscapingOff locks parity with the backend signer
// (revokesign.Canonical): HTML escaping MUST be off and there is no trailing newline,
// so a value containing &, <, or > signs byte-for-byte identically on both sides.
func TestCanonicalHTMLEscapingOff(t *testing.T) {
	got, err := CanonicalRevokeMessage("a&b", "r<x>", "n", "t")
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"org":"a&b","repo":"r<x>","nonce":"n","issued_at":"t"}`
	if string(got) != want {
		t.Fatalf("HTML escaping must be OFF, no trailing newline:\n got %q\nwant %q", got, want)
	}
}

func TestTrustedKeyEnvOverride(t *testing.T) {
	pub, _ := testKeypair(t)
	t.Setenv(envRevokePubKey, base64.StdEncoding.EncodeToString(pub))
	t.Setenv(envRevokeKeyID, "kX")
	got, id, err := TrustedKey()
	if err != nil {
		t.Fatalf("TrustedKey: %v", err)
	}
	if id != "kX" || !got.Equal(pub) {
		t.Fatalf("env override not honored: id=%q equal=%v", id, got.Equal(pub))
	}
}

func TestTrustedKeyAbsent(t *testing.T) {
	t.Setenv(envRevokePubKey, "")
	t.Setenv(envRevokeKeyID, "")
	got, _, err := TrustedKey()
	if err != nil {
		t.Fatalf("absent key must not error, got %v", err)
	}
	if got != nil {
		t.Fatalf("absent key must be nil, got %v", got)
	}
}
