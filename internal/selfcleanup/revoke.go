// Package selfcleanup is the customer-side (Action/scanner) half of the Ferralon
// self-cleanup ladder. When the free Assay Action keeps running after the backing
// GitHub App is uninstalled, the scan's ingest POST comes back HTTP 410 with a
// cryptographically-signed install-revoke body; after N=2 consecutive VERIFIED
// revokes the scanner removes its own footprint from the repository (workflow file
// + the durable state ref), degrading gracefully through a three-rung ladder.
//
// The server half (the signed 410 response) lives in the backend.
// This package only VERIFIES — it holds the baked public key, checks the
// signature, counts consecutive revokes in the StateStore, and actuates.
package selfcleanup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// RevokeSchema is the wire-format-v1 schema string on a signed install-revoke body.
const RevokeSchema = "ferralon.revoke/v1"

// RevokeBody is the HTTP-410 install-revoke response body (wire format v1, per the
// design-constants contract). The signature covers the canonical JSON of the four
// signed fields (Org, Repo, Nonce, IssuedAt) only — Schema, KeyID and Sig are
// envelope, not signed content.
type RevokeBody struct {
	Schema   string `json:"schema"`
	Org      string `json:"org"`
	Repo     string `json:"repo"`
	Nonce    string `json:"nonce"`     // 128-bit random, base64
	IssuedAt string `json:"issued_at"` // RFC3339
	KeyID    string `json:"key_id"`
	Sig      string `json:"sig"` // base64 Ed25519 signature over the canonical JSON
}

// signedFields is the exact, ordered shape the Ed25519 signature covers: exactly
// org, repo, nonce, issued_at, in that declaration order. The bytes MUST be
// byte-identical to what the backend signer produces — reconciled with dispatch 03's
// backend `revokesign.Canonical`: compact separators (no spaces), fields in this
// order, HTML escaping OFF, and NO trailing newline.
type signedFields struct {
	Org      string `json:"org"`
	Repo     string `json:"repo"`
	Nonce    string `json:"nonce"`
	IssuedAt string `json:"issued_at"`
}

// CanonicalRevokeMessage returns the exact bytes the Ed25519 signature is computed
// over: compact JSON of {org, repo, nonce, issued_at} in that field order, with HTML
// escaping DISABLED and no trailing newline — matching the backend signer byte for
// byte (dispatch 03 `revokesign.Canonical`). HTML escaping matters only if a value
// ever carries <, >, or &; org/repo/nonce/issued_at never do, but both sides fix the
// setting so the bytes provably cannot drift.
func CanonicalRevokeMessage(org, repo, nonce, issuedAt string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(signedFields{Org: org, Repo: repo, Nonce: nonce, IssuedAt: issuedAt}); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ErrBadSignature is returned when a 410 body's signature does not verify against
// the baked public key (wrong key, tampered content, malformed base64). Only a body
// that clears Verify counts as a revoke; everything else is transient.
var ErrBadSignature = errors.New("selfcleanup: revoke body signature did not verify")

// ErrSchemaMismatch is returned when the body's schema string is not RevokeSchema.
var ErrSchemaMismatch = errors.New("selfcleanup: unexpected revoke body schema")

// Verify checks b's Ed25519 signature against pub. keyID, when non-empty, must equal
// b.KeyID (rotation guard: a body signed under an unknown key id is rejected without
// even attempting the crypto). It returns nil only when the signature is valid over
// CanonicalRevokeMessage(b.Org, b.Repo, b.Nonce, b.IssuedAt).
func Verify(b RevokeBody, pub ed25519.PublicKey, keyID string) error {
	if b.Schema != RevokeSchema {
		return fmt.Errorf("%w: %q", ErrSchemaMismatch, b.Schema)
	}
	if keyID != "" && b.KeyID != keyID {
		return fmt.Errorf("%w: body key_id %q != trusted %q", ErrBadSignature, b.KeyID, keyID)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: no usable public key (len %d)", ErrBadSignature, len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(b.Sig)
	if err != nil {
		return fmt.Errorf("%w: sig not base64: %v", ErrBadSignature, err)
	}
	msg, err := CanonicalRevokeMessage(b.Org, b.Repo, b.Nonce, b.IssuedAt)
	if err != nil {
		return fmt.Errorf("%w: canonicalize: %v", ErrBadSignature, err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrBadSignature
	}
	return nil
}

// Sign produces a wire-format-v1 RevokeBody signed by priv under keyID. It exists so
// hermetic tests (and a backend keygen/fixture) can mint valid bodies; the scanner
// itself only ever calls Verify.
func Sign(priv ed25519.PrivateKey, keyID, org, repo, nonce, issuedAt string) (RevokeBody, error) {
	msg, err := CanonicalRevokeMessage(org, repo, nonce, issuedAt)
	if err != nil {
		return RevokeBody{}, err
	}
	sig := ed25519.Sign(priv, msg)
	return RevokeBody{
		Schema:   RevokeSchema,
		Org:      org,
		Repo:     repo,
		Nonce:    nonce,
		IssuedAt: issuedAt,
		KeyID:    keyID,
		Sig:      base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// parseRevokeBody decodes a 410 response body into a RevokeBody. It is strict about
// well-formed JSON but does not verify — Verify is a separate step so an unsigned or
// malformed body is classified transient, never counted.
func parseRevokeBody(raw []byte) (RevokeBody, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b RevokeBody
	if err := dec.Decode(&b); err != nil {
		// Fall back to a lenient decode: an extra field the server adds later must not
		// turn a genuine signed revoke into a transient miss. Signature still gates it.
		if err2 := json.Unmarshal(raw, &b); err2 != nil {
			return RevokeBody{}, err2
		}
	}
	return b, nil
}
