package pipeline

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// serveHandler answers every request on host with h.
func (r *fakeRegistries) serveHandler(t *testing.T, host string, h http.Handler) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	r.backends[host] = u.Host
}

// truncating declares the whole body's length and sends only its first half, as a connection
// dropped mid-download does.
func truncating(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body[:len(body)/2])
	})
}

// fallbackRun acquires nodes for one JS build in a stage, the way a scan does, and returns the
// result, the dependency cache the lane would be handed, the cache root and what Observe saw.
func fallbackRun(t *testing.T, mode DependencyCodeMode, regs *fakeRegistries, npmrc string, timeout time.Duration, p plugin.LanguagePlugin) (DependencyAcquisitionResult, string, string, []DependencyAcquisitionResult) {
	t.Helper()
	build, cache := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(build, ".npmrc"), []byte(npmrc), 0o600); err != nil {
		t.Fatal(err)
	}
	var observed []DependencyAcquisitionResult
	acq := &dependencyAcquirer{
		cfg: DependencyAcquisition{Mode: mode, CacheDir: cache, Client: regs.client, Timeout: timeout,
			Observe: func(r DependencyAcquisitionResult) { observed = append(observed, r) }},
		byDir: map[string]*acquiredBuild{},
	}
	store := artifact.NewMemStore()
	stage := dependencyAcquisition{plugin: p, acq: acq}
	// Two advisories assessed against one build share one acquisition and one Observe call.
	for _, id := range []string{"case-a", "case-b"} {
		c := &assessment.Assessment{ID: id}
		if _, err := PutArtifact(store, c, "codebase_inventory", artifact.TypeInventory, "", map[string]string{"build_dir": build, "language": "js"}); err != nil {
			t.Fatal(err)
		}
		if err := stage.Run(context.Background(), c, store); err != nil {
			t.Fatal(err)
		}
	}
	res, ok := DependencyAcquisitionOf(store, "case-a")
	if !ok {
		t.Fatal("dependency_acquisition recorded nothing")
	}
	got := acq.cacheFor(store, "case-a")
	if other := acq.cacheFor(store, "case-b"); other != got {
		t.Fatalf("cacheFor differs between cases sharing a build: %q vs %q", got, other)
	}
	return res, got, cache, observed
}

// A fetch that fails for any package, or whose inventory fails, falls back: the lane is handed no
// dependency cache, exactly as with dependency code off, and the result names why. A failure that
// is not a fetch (a lock entry with no usable integrity) and offline mode never fall back.
func TestDependencyAcquisitionFallback(t *testing.T) {
	good, other := []byte("qs tarball bytes"), []byte("lib tarball bytes")
	qs, lib := "pkg:npm/qs@6.5.2", "pkg:npm/%40corp/lib@1.0.0"
	both := inventoryPlugin{nodes: []plugin.DependencyNode{npmNode(qs, sri512(good)), npmNode(lib, sri512(other))}}
	const scoped = "registry=https://registry.test/\n@corp:registry=https://corp.test/\n"

	tests := []struct {
		name       string
		mode       DependencyCodeMode
		corp       func(*testing.T, *fakeRegistries) // how corp.test answers; nil leaves it unreachable
		npmrc      string
		timeout    time.Duration
		plugin     plugin.LanguagePlugin
		wantKind   string // "" when the lane keeps the cache
		wantDetail string
		wantRead   int
	}{
		{name: "every fetch verifies", mode: DependencyCodeFetch,
			corp: func(t *testing.T, r *fakeRegistries) { r.serve(t, "corp.test", other) }, wantRead: 2},
		{name: "registry error on one package", mode: DependencyCodeFetch,
			corp:     func(t *testing.T, r *fakeRegistries) { r.serveStatus(t, "corp.test", http.StatusBadGateway, nil) },
			wantKind: UnreadNotServed, wantDetail: lib, wantRead: 1},
		{name: "not served", mode: DependencyCodeFetch,
			corp:     func(t *testing.T, r *fakeRegistries) { r.serve(t, "corp.test", nil) },
			wantKind: UnreadNotServed, wantDetail: lib, wantRead: 1},
		{name: "auth: token refused", mode: DependencyCodeFetch,
			corp:     func(t *testing.T, r *fakeRegistries) { r.serveStatus(t, "corp.test", http.StatusUnauthorized, nil) },
			npmrc:    "//corp.test/:_authToken=${NPM_TOKEN?}\n",
			wantKind: UnreadPolicyRefused, wantDetail: lib + ": missing-credential", wantRead: 1},
		{name: "auth: no credential configured for a private registry", mode: DependencyCodeFetch,
			corp:     func(t *testing.T, r *fakeRegistries) { r.serve(t, "corp.test", other) },
			npmrc:    "//corp.test/:_authToken=\n",
			wantKind: UnreadPolicyRefused, wantDetail: lib + ": missing-credential", wantRead: 1},
		{name: "transport failure", mode: DependencyCodeFetch,
			wantKind: UnreadFetchFailed, wantDetail: lib, wantRead: 1},
		{name: "partial body", mode: DependencyCodeFetch,
			corp:     func(t *testing.T, r *fakeRegistries) { r.serveHandler(t, "corp.test", truncating(other)) },
			wantKind: UnreadFetchFailed, wantDetail: lib, wantRead: 1},
		{name: "timeout", mode: DependencyCodeFetch, timeout: time.Nanosecond,
			corp:     func(t *testing.T, r *fakeRegistries) { r.serve(t, "corp.test", other) },
			plugin:   inventoryPlugin{nodes: both.nodes},
			wantKind: UnreadCancelled, wantDetail: lib},
		{name: "inventory fails", mode: DependencyCodeFetch, plugin: failingInventoryPlugin{},
			wantKind: FallbackInventoryFailed},
		{name: "inventory outlasts the deadline", mode: DependencyCodeFetch, plugin: slowInventoryPlugin{}, timeout: 10 * time.Millisecond,
			wantKind: FallbackInventoryFailed, wantDetail: UnreadCancelled},
		{name: "no lock integrity is not a fetch failure", mode: DependencyCodeFetch,
			plugin:   inventoryPlugin{nodes: []plugin.DependencyNode{npmNode(qs, sri512(good)), npmNode(lib, "")}},
			wantRead: 1},
		{name: "offline never falls back", mode: DependencyCodeOffline},
		{name: "offline inventory failure never falls back", mode: DependencyCodeOffline, plugin: failingInventoryPlugin{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regs := newFakeRegistries()
			regs.serve(t, "registry.test", good)
			if tt.corp != nil {
				tt.corp(t, regs)
			}
			p := tt.plugin
			if p == nil {
				p = both
			}
			res, lane, cache, observed := fallbackRun(t, tt.mode, regs, scoped+tt.npmrc, tt.timeout, p)
			if res.Read != tt.wantRead {
				t.Fatalf("Read = %d, want %d (unread %+v)", res.Read, tt.wantRead, res.Unread)
			}
			if len(observed) != 1 {
				t.Fatalf("Observe called %d times for one build, want 1", len(observed))
			}
			if (observed[0].Fallback == nil) != (res.Fallback == nil) {
				t.Fatalf("Observe saw fallback %+v, the artifact records %+v", observed[0].Fallback, res.Fallback)
			}
			if tt.wantKind == "" {
				if res.Fallback != nil {
					t.Fatalf("fell back: %+v", res.Fallback)
				}
				if lane != cache {
					t.Fatalf("lane cache = %q, want %q", lane, cache)
				}
				return
			}
			if res.Fallback == nil {
				t.Fatalf("no fallback; unread %+v", res.Unread)
			}
			if res.Fallback.Kind != tt.wantKind || res.Fallback.Detail != tt.wantDetail {
				t.Fatalf("fallback = %+v, want %s %q", res.Fallback, tt.wantKind, tt.wantDetail)
			}
			if lane != "" {
				t.Fatalf("lane handed cache %q after a fallback; with dependency code off it gets none", lane)
			}
		})
	}
}

// A body cut short is never published: the cache holds nothing at the package's path, no
// temporary file survives, and a reader looking the package up finds it absent.
func TestDependencyAcquisitionPartialBodyNotRead(t *testing.T) {
	body := []byte("a tarball long enough to cut in half")
	digest := sri512(body)
	for _, tc := range []struct {
		name string
		h    http.Handler
	}{
		{"short body under a full Content-Length", truncating(body)},
		{"body cut short with no Content-Length", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body[:len(body)/2])
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			regs := newFakeRegistries()
			regs.serveHandler(t, "registry.test", tc.h)
			res, lane, cache, _ := fallbackRun(t, DependencyCodeFetch, regs, "registry=https://registry.test/\n", 0,
				inventoryPlugin{nodes: []plugin.DependencyNode{npmNode("pkg:npm/qs@6.5.2", digest)}})
			if res.Read != 0 || len(res.Unread) != 1 {
				t.Fatalf("read %d unread %+v, want the package unread", res.Read, res.Unread)
			}
			if r := res.Unread[0].Reason; r != UnreadFetchFailed && r != UnreadIntegrityMismatch {
				t.Fatalf("unread reason %q, want fetch_failed or integrity_mismatch", r)
			}
			if res.Fallback == nil || lane != "" {
				t.Fatalf("fallback %+v, lane cache %q: a partial fetch must read as off", res.Fallback, lane)
			}
			_, err := artifactcache.NewDiskStore(cache).Lookup(context.Background(), artifactcache.Ref{PURL: "pkg:npm/qs@6.5.2", Digest: digest})
			if !errors.Is(err, artifactcache.ErrDeclaredAbsent) {
				t.Fatalf("cache lookup err = %v, want ErrDeclaredAbsent", err)
			}
			var files []string
			_ = filepath.WalkDir(cache, func(path string, de fs.DirEntry, err error) error {
				if err == nil && !de.IsDir() {
					files = append(files, strings.TrimPrefix(path, cache))
				}
				return nil
			})
			if len(files) != 0 {
				t.Fatalf("cache holds %v after a partial fetch", files)
			}
		})
	}
}
