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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
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

// Credentialed reports whether purl's registry has an auth entry in this policy: the same
// RegistryConfig the fetch consults before it presents a credential, so a caller deciding where
// the bytes may be kept never re-derives which registries are authenticated.
func (p Policy) Credentialed(purl string) (bool, error) {
	_, reg, err := p.backendFor(purl)
	if err != nil {
		return false, err
	}
	return reg.AuthConfigured, nil
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
	// Fetched is set when this Acquire fetched the bytes from the registry; a cache hit
	// leaves it false. It is not persisted.
	Fetched bool `json:"-"`
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
	sleep  func(context.Context, time.Duration) error

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
	return &Acquirer{root: root, client: client, now: time.Now, sleep: sleepCtx}
}

// SetRetrySleep replaces how Acquire waits between attempts at a transient failure; the
// default waits on a timer and stops when ctx ends. Tests use it to keep time out of the
// retry path.
func (a *Acquirer) SetRetrySleep(sleep func(context.Context, time.Duration) error) {
	a.sleep = sleep
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

	// 5. FETCH, retrying a transient registry failure within retryWait's bounds.
	var prev error
	for attempt := 1; ; attempt++ {
		rec, err := a.fetch(ctx, ref, policy, u, host, creds, algo, raw, canonical, path)
		if err == nil {
			return rec, nil
		}
		// A retry the caller's deadline cut short adds nothing to what the registry already
		// said: the earlier failure is the evidence. A first attempt cut short has none.
		if prev != nil && ctx.Err() != nil && !artifactcache.IsPartiality(err) {
			return AcquisitionRecord{}, prev
		}
		wait, ok := a.retryWait(ctx, err, attempt)
		if !ok || a.sleep(ctx, wait) != nil {
			return AcquisitionRecord{}, err
		}
		prev = err
	}
}

// Retry bounds for a transient registry failure (ErrRegistryUnavailable).
const (
	// maxFetchAttempts caps the requests one Acquire sends.
	maxFetchAttempts = 3
	// retryBackoff is the first wait when the registry names none; it doubles per attempt.
	retryBackoff = time.Second
	// maxRetryWait caps one wait. A Retry-After longer than this is not waited for.
	maxRetryWait = 30 * time.Second
)

// retryWait returns how long to wait before attempt+1, or false when err is not transient,
// attempt was the last, the wait exceeds maxRetryWait, or it would end at or past ctx's
// deadline: a retry never extends the caller's deadline.
func (a *Acquirer) retryWait(ctx context.Context, err error, attempt int) (time.Duration, bool) {
	var fr *artifactcache.FetchReason
	if attempt >= maxFetchAttempts || ctx.Err() != nil || !errors.As(err, &fr) || !errors.Is(fr, artifactcache.ErrRegistryUnavailable) {
		return 0, false
	}
	wait := retryBackoff << (attempt - 1)
	if fr.RetryAfter > 0 {
		wait = fr.RetryAfter
	}
	if wait > maxRetryWait {
		return 0, false
	}
	if dl, ok := ctx.Deadline(); ok && !a.now().Add(wait).Before(dl) {
		return 0, false
	}
	return wait, true
}

// sleepCtx waits d, or returns ctx's error if it ends first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// fetch sends one GET for the checked target u and publishes the verified bytes, or returns
// one typed outcome. The credential is attached ONLY for the bound allowlisted host.
func (a *Acquirer) fetch(ctx context.Context, ref artifactcache.Ref, policy Policy, u *url.URL, host string, creds RegistryCredentials, algo string, raw []byte, canonical, path string) (AcquisitionRecord, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return AcquisitionRecord{}, err
	}
	presented := false
	if c := creds.For(host); !c.IsEmpty() {
		c.ApplyTo(req)
		presented = true
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
		return AcquisitionRecord{}, transportFailure(ctx, ref.PURL, host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A registry that refuses the request is not evidence the artifact is absent: either
		// the run had no credential to present (no auth entry, or one whose token is unset),
		// or the one it presented was refused. A host a redirect reached was never sent the
		// registry's credential, and a storage host commonly refuses a key it does not hold,
		// so its 401/403 reads as not served, unless the redirect presented that host's own
		// bound credential: then the refusal is of a token this run sent.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			switch {
			case answeredBy(resp, host):
				code := artifactcache.PolicyMissingCredential
				if presented {
					code = artifactcache.PolicyCredentialRejected
				}
				return AcquisitionRecord{}, &artifactcache.PolicyReason{PURL: ref.PURL, Host: host, Code: code}
			case sentCredential(resp):
				h, _ := canonicalHost(resp.Request.URL)
				return AcquisitionRecord{}, &artifactcache.PolicyReason{PURL: ref.PURL, Host: h, Code: artifactcache.PolicyCredentialRejected}
			}
		}
		// A throttle, timeout or server error says nothing about whether the artifact exists.
		if code := unavailableStatus(resp.StatusCode); code != "" {
			return AcquisitionRecord{}, &artifactcache.FetchReason{PURL: ref.PURL, Host: host, Code: code, Status: resp.StatusCode, RetryAfter: retryAfter(resp.Header.Get("Retry-After"), a.now())}
		}
		// Not found / not served: nothing acquired — honest ErrDeclaredAbsent, never an
		// empty success.
		return AcquisitionRecord{}, artifactcache.ErrDeclaredAbsent
	}

	// 6. VERIFY (streaming) → 8. ATOMIC PUBLISH. Verified bytes reach the final path only via
	// os.Rename after the hash matches; nothing is readable at <path> until then.
	body := &bodyReader{ReadCloser: resp.Body}
	resp.Body = body
	rec, err := a.verifyAndPublish(resp, ref, algo, raw, canonical, path)
	if err != nil {
		if body.err != nil {
			return AcquisitionRecord{}, transportFailure(ctx, ref.PURL, host, body.err)
		}
		return AcquisitionRecord{}, err
	}
	return rec, nil
}

// answeredBy reports whether resp came from host itself rather than from a host a redirect
// reached.
func answeredBy(resp *http.Response, host string) bool {
	if resp.Request == nil || resp.Request.URL == nil {
		return false
	}
	h, err := canonicalHost(resp.Request.URL)
	return err == nil && h == host
}

// sentCredential reports whether the request resp answers carried an Authorization header: the
// redirect policy attaches one only from the credential bound to that request's own host.
func sentCredential(resp *http.Response) bool {
	return resp.Request != nil && resp.Request.URL != nil && resp.Request.Header.Get("Authorization") != ""
}

// unavailableStatus is the Fetch* code for a status that marks the registry, not the
// artifact, as the reason nothing was served, or "".
func unavailableStatus(status int) string {
	switch {
	case status == http.StatusTooManyRequests:
		return artifactcache.FetchRateLimited
	case status == http.StatusRequestTimeout:
		return artifactcache.FetchTimeout
	case status >= 500 && status <= 599:
		return artifactcache.FetchServerError
	}
	return ""
}

// retryAfter parses a Retry-After header, as delay-seconds or an HTTP date, into a wait
// from now. Absent, malformed or already past is zero.
func retryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		// Past the cap every value is refused alike; clamping keeps the multiply in range.
		return time.Duration(min(secs, int64(maxRetryWait/time.Second)+1)) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// transportFailure classifies an error the transport returned for host. An error the
// caller's context could itself have caused is returned unchanged, as is one that names no
// registry condition; the rest become a FetchReason, dropping the wrapped error, whose text
// can carry the URL.
func transportFailure(ctx context.Context, purl, host string, err error) error {
	if ctx.Err() != nil {
		return err
	}
	var dnsErr *net.DNSError
	var opErr *net.OpError
	var netErr net.Error
	code := ""
	switch {
	case errors.As(err, &dnsErr):
		code = artifactcache.FetchDNSFailure
	case errors.As(err, &opErr) && opErr.Op == "dial":
		code = artifactcache.FetchConnectFailure
	case errors.As(err, &netErr) && netErr.Timeout():
		code = artifactcache.FetchTimeout
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		code = artifactcache.FetchConnectionReset
	default:
		return err
	}
	return &artifactcache.FetchReason{PURL: purl, Host: host, Code: code}
}

// bodyReader records the first error reading the response body, so a failure while
// publishing can be told apart as the registry's rather than the cache directory's.
type bodyReader struct {
	io.ReadCloser
	err error
}

func (b *bodyReader) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF && b.err == nil {
		b.err = err
	}
	return n, err
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
		Fetched:    true,
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
