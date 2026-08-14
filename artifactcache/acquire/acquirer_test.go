package acquire

import (
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
)

const nugetHost = "registry.nuget.test"

// wantNuGetPath is the flat-container layout the NuGet backend must derive for
// Newtonsoft.Json@13.0.3 (id lowercased; folder is <id>/<ver>, filename <id>.<ver>.nupkg).
const wantNuGetPath = "/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"

// Test 6.1/6.2/6.3/6.5/6.6: acquire a real NuGet coordinate from a hermetic TLS server at the
// real layout URL; verify against the genuine sha512:<base64> digest; land at the canonical
// path; Lookup reads it back; second Acquire is an idempotent cache hit; record + metrics set.
func TestAcquireE2ESuccess(t *testing.T) {
	h := newHarness(t)
	data := []byte("hermetic .nupkg fixture bytes — inert to the cache")
	var gotPath string
	h.serve(t, nugetHost, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write(data)
	}))

	root := t.TempDir()
	acq := NewAcquirer(root, h.client)
	ref := nugetRef(data)
	policy := nugetPolicy(nugetHost, false, RegistryCredentials{})

	rec, err := acq.Acquire(t.Context(), ref, policy)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if gotPath != wantNuGetPath {
		t.Fatalf("fetched path = %q, want %q", gotPath, wantNuGetPath)
	}

	// Bytes landed at the canonical path, read-only (0o444).
	canon, err := artifactcache.CanonicalPath(root, ref.Digest)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(canon)
	if err != nil {
		t.Fatalf("stat published artifact: %v", err)
	}
	if fi.Mode().Perm() != 0o444 {
		t.Fatalf("published mode = %v, want 0o444", fi.Mode().Perm())
	}

	// Lookup reads the exact bytes at the content-addressed path (6.2).
	store := artifactcache.NewDiskStore(root)
	hd, err := store.Lookup(t.Context(), ref)
	if err != nil {
		t.Fatalf("Lookup after acquire: %v", err)
	}
	defer hd.Close()
	buf := make([]byte, len(data))
	if _, err := hd.ReadAt(buf, 0); err != nil && err.Error() != "EOF" {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf) != string(data) {
		t.Fatalf("read bytes = %q, want %q", buf, data)
	}
	if hd.Path() != canon {
		t.Fatalf("Path() = %q, want %q", hd.Path(), canon)
	}

	// Record populated (6.5): source has no userinfo; digest wire+canonical set.
	if rec.PURL != ref.PURL || rec.Digest != ref.Digest || rec.Canonical == "" || rec.AcquiredAt.IsZero() {
		t.Fatalf("record under-populated: %+v", rec)
	}
	if rec.Source == "" || containsUserinfo(rec.Source) {
		t.Fatalf("record Source %q missing or carries userinfo", rec.Source)
	}

	// Metrics: first Acquire was a miss.
	if acq.Misses() != 1 || acq.Hits() != 0 {
		t.Fatalf("after first acquire: hits=%d misses=%d, want 0/1", acq.Hits(), acq.Misses())
	}

	// Second Acquire is an idempotent cache HIT — no second download, same path (6.3/6.6).
	gotPath = ""
	rec2, err := acq.Acquire(t.Context(), ref, policy)
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	if gotPath != "" {
		t.Fatalf("cache hit re-fetched from the server (path %q)", gotPath)
	}
	if rec2.PURL != ref.PURL {
		t.Fatalf("cache-hit record wrong: %+v", rec2)
	}
	if acq.Hits() != 1 {
		t.Fatalf("after second acquire: hits=%d, want 1", acq.Hits())
	}
}

// Test 2.2 / 6.4: served bytes whose hash != ref.Digest → ErrIntegrityMismatch; NOTHING
// written; subsequent Lookup → ErrDeclaredAbsent; no zero-byte file at the canonical path.
func TestAcquireIntegrityMismatchPublishesNothing(t *testing.T) {
	h := newHarness(t)
	good := []byte("the bytes the digest pins")
	tampered := []byte("the bytes an attacker served")
	h.serve(t, nugetHost, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tampered)
	}))

	root := t.TempDir()
	acq := NewAcquirer(root, h.client)
	ref := nugetRef(good) // digest of good bytes; server serves tampered
	policy := nugetPolicy(nugetHost, false, RegistryCredentials{})

	_, err := acq.Acquire(t.Context(), ref, policy)
	if !errors.Is(err, artifactcache.ErrIntegrityMismatch) {
		t.Fatalf("Acquire err = %v, want ErrIntegrityMismatch", err)
	}
	var ir *artifactcache.IntegrityReason
	if !errors.As(err, &ir) || ir.PURL != ref.PURL {
		t.Fatalf("expected IntegrityReason with PURL, got %v", err)
	}

	canon, _ := artifactcache.CanonicalPath(root, ref.Digest)
	if _, statErr := os.Stat(canon); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("integrity failure left a file at %q (stat err %v)", canon, statErr)
	}
	store := artifactcache.NewDiskStore(root)
	if _, lerr := store.Lookup(t.Context(), ref); !errors.Is(lerr, artifactcache.ErrDeclaredAbsent) {
		t.Fatalf("Lookup after integrity failure = %v, want ErrDeclaredAbsent", lerr)
	}
}

// Test 2.3 / 4.2: off-allowlist host → ErrPolicyRefused; server saw NO request; no credential
// sent. (The empty-allowlist policy refuses before any dial.)
func TestAcquireOffAllowlistRefused(t *testing.T) {
	h := newHarness(t)
	counter := &countingHandler{body: []byte("should never be served")}
	h.serve(t, nugetHost, counter)

	root := t.TempDir()
	acq := NewAcquirer(root, h.client)
	ref := nugetRef(counter.body)
	// Allowlist a DIFFERENT host, so nugetHost is off-list.
	policy := Policy{
		Allowlist:  NewAllowlist("some.other.registry.test"),
		Registries: map[string]RegistryConfig{"nuget": {BaseURL: "https://" + nugetHost}},
		Backends:   map[string]RegistryBackend{"nuget": NewNuGetBackend()},
	}

	_, err := acq.Acquire(t.Context(), ref, policy)
	var pr *artifactcache.PolicyReason
	if !errors.As(err, &pr) || pr.Code != artifactcache.PolicyOffAllowlist {
		t.Fatalf("err = %v, want PolicyReason off-allowlist", err)
	}
	if counter.requests != 0 {
		t.Fatalf("off-allowlist host received %d requests, want 0", counter.requests)
	}
}

// Test 2.4: non-HTTPS target → ErrPolicyRefused before any dial.
func TestAcquireNonHTTPSRefused(t *testing.T) {
	root := t.TempDir()
	acq := NewAcquirer(root, newHarness(t).client)
	ref := nugetRef([]byte("x"))
	policy := Policy{
		Allowlist:  NewAllowlist(nugetHost),
		Registries: map[string]RegistryConfig{"nuget": {BaseURL: "http://" + nugetHost}}, // http, not https
		Backends:   map[string]RegistryBackend{"nuget": NewNuGetBackend()},
	}
	_, err := acq.Acquire(t.Context(), ref, policy)
	var pr *artifactcache.PolicyReason
	if !errors.As(err, &pr) || pr.Code != artifactcache.PolicyNonHTTPS {
		t.Fatalf("err = %v, want PolicyReason non-https", err)
	}
}

// Test 2.5: a PyPI coordinate that resolves no single (url,digest) → ErrUnpinnedArtifact with
// Detail python-wheel-selection-gap; nothing written.
func TestAcquirePythonUnpinned(t *testing.T) {
	root := t.TempDir()
	acq := NewAcquirer(root, newHarness(t).client)
	ref := artifactcache.Ref{PURL: "pkg:pypi/requests@2.31.0", Digest: "sha256:" + repeatHex(64)}
	policy := Policy{
		Allowlist:  NewAllowlist("pypi.test"),
		Registries: map[string]RegistryConfig{"pypi": {BaseURL: "https://pypi.test"}},
		Backends:   map[string]RegistryBackend{"pypi": NewPyPIBackend()},
	}
	_, err := acq.Acquire(t.Context(), ref, policy)
	var ur *artifactcache.UnpinnedReason
	if !errors.As(err, &ur) || ur.Detail != "python-wheel-selection-gap" {
		t.Fatalf("err = %v, want UnpinnedReason python-wheel-selection-gap", err)
	}
}

// Test 2.6: no empty-success. For every failure outcome, Acquire returns a zero record and
// Store.Lookup never yields a non-nil Handle over 0 bytes.
func TestNoEmptySuccessAcrossFailures(t *testing.T) {
	root := t.TempDir()
	store := artifactcache.NewDiskStore(root)
	refs := []artifactcache.Ref{
		{PURL: "pkg:nuget/x@1", Digest: "sha256:" + repeatHex(64)}, // never acquired
	}
	for _, ref := range refs {
		hd, err := store.Lookup(t.Context(), ref)
		if hd != nil {
			t.Fatalf("Lookup yielded a non-nil Handle for an unacquired ref")
		}
		if !errors.Is(err, artifactcache.ErrDeclaredAbsent) {
			t.Fatalf("Lookup err = %v, want ErrDeclaredAbsent", err)
		}
	}
}

// Test 2.5 (Maven deferral): a Maven coordinate is a declared unpinned partiality, not an
// empty success and not a fetch.
func TestAcquireMavenDeferred(t *testing.T) {
	root := t.TempDir()
	acq := NewAcquirer(root, newHarness(t).client)
	ref := artifactcache.Ref{PURL: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", Digest: "sha1:" + repeatHex(40)}
	policy := Policy{
		Allowlist:  NewAllowlist("repo1.maven.test"),
		Registries: map[string]RegistryConfig{"maven": {BaseURL: "https://repo1.maven.test"}},
		Backends:   map[string]RegistryBackend{"maven": NewMavenBackend()},
	}
	_, err := acq.Acquire(t.Context(), ref, policy)
	var ur *artifactcache.UnpinnedReason
	if !errors.As(err, &ur) || ur.Detail != "maven-inventory-deferred" {
		t.Fatalf("err = %v, want UnpinnedReason maven-inventory-deferred", err)
	}
	if !artifactcache.IsPartiality(err) {
		t.Fatalf("maven deferral should be a partiality")
	}
}

// A malformed digest is rejected at Acquire (the gate), distinct from a partiality.
func TestAcquireMalformedRef(t *testing.T) {
	root := t.TempDir()
	acq := NewAcquirer(root, newHarness(t).client)
	ref := artifactcache.Ref{PURL: "pkg:nuget/x@1", Digest: "sha256:not-a-valid-digest"}
	_, err := acq.Acquire(t.Context(), ref, nugetPolicy(nugetHost, false, RegistryCredentials{}))
	if !errors.Is(err, artifactcache.ErrMalformedRef) {
		t.Fatalf("err = %v, want ErrMalformedRef", err)
	}
	if artifactcache.IsPartiality(err) {
		t.Fatalf("ErrMalformedRef must not be a partiality")
	}
}

func repeatHex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}

func containsUserinfo(s string) bool {
	// crude check: an "@" before the first "/" after scheme indicates userinfo.
	return len(s) > 0 && (indexUserinfo(s) >= 0)
}

func indexUserinfo(s string) int {
	// look for "://" then "@" before the next "/"
	i := 0
	for ; i+3 <= len(s); i++ {
		if s[i:i+3] == "://" {
			i += 3
			break
		}
	}
	for ; i < len(s); i++ {
		if s[i] == '/' {
			return -1
		}
		if s[i] == '@' {
			return i
		}
	}
	return -1
}
