package acquire

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
)

// maxRedirectHops reinstates a finite redirect cap. Overriding http.Client.CheckRedirect
// drops the stdlib default's 10-hop stop, so a redirect loop between allowlisted hosts would
// otherwise spin unbounded (DoS). We cap at 10, matching the stdlib default.
const maxRedirectHops = 10

// hasherFor returns a fresh hash.Hash for the closed set of algorithms. algo has already
// cleared DecodeDigest, so the default is unreachable in practice.
func hasherFor(algo string) (hash.Hash, bool) {
	switch algo {
	case "sha1":
		return sha1.New(), true
	case "sha256":
		return sha256.New(), true
	case "sha512":
		return sha512.New(), true
	default:
		return nil, false
	}
}

// Policy owns the acquisition trust surface: the closed HTTPS allowlist, per-ecosystem
// registry config, the per-ecosystem backends, and the registry credentials. Keeping
// fetch/credential in the shared Acquirer core (not per-backend) makes the credential
// boundary a single audited surface.
type Policy struct {
	Allowlist   Allowlist
	Registries  map[string]RegistryConfig // ecosystem -> config
	Backends    map[string]RegistryBackend
	Credentials RegistryCredentials
}

// backendFor returns the backend and config for ref's ecosystem.
func (p Policy) backendFor(purl string) (RegistryBackend, RegistryConfig, error) {
	eco, ok := ecosystemOf(purl)
	if !ok {
		return nil, RegistryConfig{}, &artifactcache.UnpinnedReason{PURL: purl, Detail: "purl-has-no-ecosystem"}
	}
	b, ok := p.Backends[eco]
	if !ok {
		return nil, RegistryConfig{}, &artifactcache.PolicyReason{PURL: purl, Code: artifactcache.PolicyNoBackend}
	}
	return b, p.Registries[eco], nil
}

// AcquisitionRecord is the provenance emitted on a verified publish (design §8; PLAN-402
// reads it). It is emitted ONLY on success, so a record never describes a refused or
// integrity-failed artifact. It carries NO credential and NO userinfo in Source.
type AcquisitionRecord struct {
	PURL       string    `json:"purl"`
	Target     string    `json:"target"`    // resolved platform/target; empty when unknown
	Source     string    `json:"source"`    // post-redirect host+path, no userinfo, no credential
	Digest     string    `json:"digest"`    // wire form (algorithm:base64|hex)
	Canonical  string    `json:"canonical"` // "<algo>:<hex>"
	AcquiredAt time.Time `json:"acquiredAt"`
}

// Acquirer is the write side of the cache. It fetches, verifies in-process, and publishes
// verified bytes to the canonical content-addressed path — or publishes NOTHING. It is a
// SEPARATE type from Store/Handle (noexec layer-1 does not walk it) and carries no
// *exec.Cmd / Run()-able. It shares the cache root with a Store so a published artifact is
// exactly what Store.Lookup reads.
type Acquirer struct {
	root   string
	client *http.Client // transport only; CheckRedirect is installed per-Acquire
	now    func() time.Time

	hits   atomic.Int64
	misses atomic.Int64
}

// NewAcquirer returns an Acquirer publishing under root. The optional client supplies the
// transport (tests inject httptest's client/transport); its CheckRedirect is always replaced
// per-Acquire with the hardened policy check, so any caller-supplied CheckRedirect is ignored
// by design.
func NewAcquirer(root string, client *http.Client) *Acquirer {
	if client == nil {
		client = &http.Client{}
	}
	return &Acquirer{root: root, client: client, now: time.Now}
}

// Hits and Misses expose the cache-hit instrumentation (design §4.7 / PLAN-400 input).
func (a *Acquirer) Hits() int64   { return a.hits.Load() }
func (a *Acquirer) Misses() int64 { return a.misses.Load() }

// Acquire fetches ref's artifact per policy, verifies its digest in-process, and atomically
// publishes the verified bytes to the content-addressed path — or returns one typed taxonomy
// outcome and publishes nothing. On a cache hit it returns the recorded provenance without a
// re-download. Credentials are taken from ctx (WithRegistryCredentials) if present, else from
// policy.Credentials.
func (a *Acquirer) Acquire(ctx context.Context, ref artifactcache.Ref, policy Policy) (AcquisitionRecord, error) {
	// 1. DECODE-VALIDATE GATE — before any path derivation.
	algo, raw, err := artifactcache.DecodeDigest(ref.Digest)
	if err != nil {
		var mr *artifactcache.MalformedReason
		if errors.As(err, &mr) {
			mr.PURL = ref.PURL // enrich with the coordinate; still ErrMalformedRef
		}
		return AcquisitionRecord{}, err
	}
	canonical := algo + ":" + hex.EncodeToString(raw)
	path := artifactcache.CanonicalPathFromBytes(a.root, algo, raw)

	// 3. CACHE CHECK — a published artifact means a HIT; return recorded provenance.
	if rec, ok := a.readRecord(path); ok {
		a.hits.Add(1)
		return rec, nil
	}
	a.misses.Add(1)

	// 4. POLICY / RESOLVE. Backend maps the coordinate to a URL (may be ErrUnpinnedArtifact).
	backend, reg, err := policy.backendFor(ref.PURL)
	if err != nil {
		return AcquisitionRecord{}, err
	}
	fetchURL, err := backend.ResolveURL(ref, reg)
	if err != nil {
		return AcquisitionRecord{}, err // ErrUnpinnedArtifact (Python / Maven) or refusal
	}

	creds := policy.Credentials
	if rc := RegistryCredentialsFrom(ctx); len(rc.byHost) > 0 {
		creds = rc
	}

	u, host, err := a.checkTarget(ref.PURL, fetchURL, reg, policy.Allowlist, creds)
	if err != nil {
		return AcquisitionRecord{}, err // ErrPolicyRefused, no fetch, no credential attached
	}

	// 5. FETCH — plain GET; credential attached ONLY for the bound allowlisted host.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return AcquisitionRecord{}, err
	}
	if c := creds.For(host); !c.IsEmpty() {
		c.ApplyTo(req)
	}

	client := *a.client
	client.CheckRedirect = a.redirectPolicy(ref.PURL, policy.Allowlist, creds)

	resp, err := client.Do(req)
	if err != nil {
		// A CheckRedirect refusal is wrapped in *url.Error → unwrap to the PolicyReason.
		var pr *artifactcache.PolicyReason
		if errors.As(err, &pr) {
			return AcquisitionRecord{}, pr
		}
		return AcquisitionRecord{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Not found / not served: nothing acquired — honest ErrDeclaredAbsent, never an
		// empty success. (A 401 on a private registry is pre-empted by the missing-credential
		// refusal in checkTarget.)
		return AcquisitionRecord{}, artifactcache.ErrDeclaredAbsent
	}

	// 6. VERIFY (streaming) → 8. ATOMIC PUBLISH. Verified bytes reach the final path only via
	// os.Rename after the hash matches; nothing is readable at <path> until then.
	rec, err := a.verifyAndPublish(resp, ref, algo, raw, canonical, path)
	if err != nil {
		return AcquisitionRecord{}, err
	}
	return rec, nil
}

// checkTarget canonicalizes and validates the initial fetch target: HTTPS-only, on the
// closed allowlist, no userinfo; and — for a private (RequireAuth) registry — a bound
// credential must be present (else missing-credential, not a silent anonymous fetch that
// 401s into a false miss). Returns the parsed URL and canonical host, or ErrPolicyRefused.
func (a *Acquirer) checkTarget(purl, fetchURL string, reg RegistryConfig, allow Allowlist, creds RegistryCredentials) (*url.URL, string, error) {
	u, err := url.Parse(fetchURL)
	if err != nil {
		return nil, "", &artifactcache.PolicyReason{PURL: purl, Host: "", Code: artifactcache.PolicyUserinfoInURL}
	}
	if u.Scheme != "https" {
		return nil, "", &artifactcache.PolicyReason{PURL: purl, Host: u.Hostname(), Code: artifactcache.PolicyNonHTTPS}
	}
	host, err := canonicalHost(u)
	if err != nil {
		return nil, "", &artifactcache.PolicyReason{PURL: purl, Host: u.Host, Code: artifactcache.PolicyUserinfoInURL}
	}
	if !allow.Allows(host) {
		return nil, "", &artifactcache.PolicyReason{PURL: purl, Host: host, Code: artifactcache.PolicyOffAllowlist}
	}
	if reg.RequireAuth && creds.For(host).IsEmpty() {
		return nil, "", &artifactcache.PolicyReason{PURL: purl, Host: host, Code: artifactcache.PolicyMissingCredential}
	}
	return u, host, nil
}

// redirectPolicy returns the hardened CheckRedirect (security-gate change #3+#4). On EVERY
// hop it: enforces the finite hop cap; rejects a URL with userinfo; refuses an HTTPS->HTTP
// downgrade (no cleartext auth); re-checks the target host against the allowlist; strips any
// carried Authorization and re-derives it from the NEW host's bound credential — so a
// credential bound to host A is never re-sent to host B.
func (a *Acquirer) redirectPolicy(purl string, allow Allowlist, creds RegistryCredentials) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirectHops {
			return &artifactcache.PolicyReason{PURL: purl, Host: req.URL.Hostname(), Code: artifactcache.PolicyRedirectHopCap}
		}
		if req.URL.Scheme != "https" {
			return &artifactcache.PolicyReason{PURL: purl, Host: req.URL.Hostname(), Code: artifactcache.PolicyRedirectDowngrade}
		}
		host, err := canonicalHost(req.URL)
		if err != nil {
			return &artifactcache.PolicyReason{PURL: purl, Host: req.URL.Host, Code: artifactcache.PolicyUserinfoInURL}
		}
		if !allow.Allows(host) {
			return &artifactcache.PolicyReason{PURL: purl, Host: host, Code: artifactcache.PolicyRedirectOffAllowlist}
		}
		// Never forward A's Authorization to B; re-derive from the new host's bound credential.
		req.Header.Del("Authorization")
		if c := creds.For(host); !c.IsEmpty() {
			c.ApplyTo(req)
		}
		return nil
	}
}

// verifyAndPublish streams resp.Body through both a temp file (in the destination shard dir,
// so os.Rename is atomic and same-filesystem) and the algorithm's hasher, compares the hash
// to the expected raw digest, and — only on a match — chmods 0o444 and renames into place. On
// mismatch it discards the temp file and returns ErrIntegrityMismatch, publishing nothing.
func (a *Acquirer) verifyAndPublish(resp *http.Response, ref artifactcache.Ref, algo string, raw []byte, canonical, path string) (AcquisitionRecord, error) {
	h, ok := hasherFor(algo)
	if !ok { // unreachable: algo cleared DecodeDigest
		return AcquisitionRecord{}, &artifactcache.MalformedReason{PURL: ref.PURL, Algo: algo, Detail: "no hasher for algorithm"}
	}

	shardDir := filepath.Dir(path)
	if err := os.MkdirAll(shardDir, 0o755); err != nil {
		return AcquisitionRecord{}, err
	}
	tmp, err := os.CreateTemp(shardDir, ".acquire-*.tmp")
	if err != nil {
		return AcquisitionRecord{}, err
	}
	tmpName := tmp.Name()
	// Ensure the temp file never lingers on any error path below.
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		return AcquisitionRecord{}, err
	}
	if err := tmp.Close(); err != nil {
		return AcquisitionRecord{}, err
	}

	got := h.Sum(nil)
	if !hmacFreeEqual(got, raw) {
		return AcquisitionRecord{}, &artifactcache.IntegrityReason{
			PURL:              ref.PURL,
			Algo:              algo,
			ExpectedCanonical: canonical,
			GotCanonical:      algo + ":" + hex.EncodeToString(got),
		}
	}

	// Read-only before publish, so the served artifact is immutable at rest.
	if err := os.Chmod(tmpName, 0o444); err != nil {
		return AcquisitionRecord{}, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return AcquisitionRecord{}, err
	}
	committed = true

	rec := AcquisitionRecord{
		PURL:       ref.PURL,
		Target:     "", // resolved wheel/target tag when known (Python); empty otherwise
		Source:     sourceString(resp),
		Digest:     ref.Digest,
		Canonical:  canonical,
		AcquiredAt: a.now().UTC(),
	}
	a.writeRecord(path, rec)
	return rec, nil
}

// sourceString is the post-redirect final host+path with NO userinfo and NO credential — the
// provenance Source the AcquisitionRecord stores. It reads resp.Request.URL, which is the URL
// actually fetched after any redirects.
func sourceString(resp *http.Response) string {
	fu := resp.Request.URL
	return (&url.URL{Scheme: fu.Scheme, Host: fu.Host, Path: fu.Path}).String()
}

// recordPath is the sidecar path beside the content-addressed artifact.
func recordPath(path string) string { return path + ".record.json" }

// writeRecord persists the provenance sidecar beside the artifact (best-effort; a sidecar
// write failure does not unpublish a verified artifact).
func (a *Acquirer) writeRecord(path string, rec AcquisitionRecord) {
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = os.WriteFile(recordPath(path), b, 0o444)
}

// readRecord reads the provenance sidecar for a cached artifact. It returns ok=false when the
// artifact file is absent (a genuine miss) — the artifact's presence, not the sidecar's, is
// what defines a cache hit.
func (a *Acquirer) readRecord(path string) (AcquisitionRecord, bool) {
	if _, err := os.Stat(path); err != nil {
		return AcquisitionRecord{}, false // artifact absent → miss
	}
	var rec AcquisitionRecord
	if b, err := os.ReadFile(recordPath(path)); err == nil {
		_ = json.Unmarshal(b, &rec)
	}
	return rec, true
}

// hmacFreeEqual is a plain byte compare of two digests (both are public hash outputs, so a
// constant-time compare is unnecessary; named to make the "no secret compared here" intent
// explicit).
func hmacFreeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
