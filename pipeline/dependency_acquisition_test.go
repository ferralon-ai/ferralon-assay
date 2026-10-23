package pipeline

import (
	"context"
	"crypto/sha1" //nolint:gosec // lock SRI fixture
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const acqSecret = "ACQ_SECRET_TOKEN_v1_MUSTNOTLEAK"

// inventoryPlugin answers ResolveInventory with a fixed node set and nothing else.
type inventoryPlugin struct {
	plugin.StubPlugin
	nodes []plugin.DependencyNode
}

func (inventoryPlugin) Language() string { return "js" }
func (p inventoryPlugin) ResolveInventory(context.Context, plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return plugin.DependencyInventory{Partiality: plugin.Complete(), Nodes: p.nodes}, nil
}

// fakeRegistries maps fake registry hostnames onto local TLS listeners and records every request
// each host received, with the Authorization header it carried.
type fakeRegistries struct {
	mu       sync.Mutex
	backends map[string]string
	requests map[string][]string // host -> Authorization of each request
	client   *http.Client
}

func newFakeRegistries() *fakeRegistries {
	r := &fakeRegistries{backends: map[string]string{}, requests: map[string][]string{}}
	r.client = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			real, ok := r.backends[host]
			if !ok {
				return nil, &net.AddrError{Err: "unknown test host", Addr: host}
			}
			return (&net.Dialer{}).DialContext(ctx, network, real)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // hermetic self-signed test cert
	}}
	return r
}

// serve answers every request on host with body; a nil body answers 404.
func (r *fakeRegistries) serve(t *testing.T, host string, body []byte) {
	t.Helper()
	r.serveStatus(t, host, 0, body)
}

// serveStatus answers every request on host with status when it is non-zero, else as serve.
func (r *fakeRegistries) serveStatus(t *testing.T, host string, status int, body []byte) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.requests[host] = append(r.requests[host], req.Header.Get("Authorization"))
		r.mu.Unlock()
		switch {
		case status != 0:
			w.WriteHeader(status)
		case body == nil:
			http.NotFound(w, req)
		default:
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	r.backends[host] = u.Host
}

func (r *fakeRegistries) seen(host string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requests[host]...)
}

func sri1(b []byte) string {
	sum := sha1.Sum(b) //nolint:gosec // lock SRI fixture
	return "sha1:" + base64.StdEncoding.EncodeToString(sum[:])
}

func sri512(b []byte) string {
	sum := sha512.Sum512(b)
	return "sha512:" + base64.StdEncoding.EncodeToString(sum[:])
}

func npmNode(purl, digest string) plugin.DependencyNode {
	return plugin.DependencyNode{ID: purl, PURL: purl, Artifact: plugin.DependencyArtifact{Digest: digest}}
}

// seedCache writes b at the canonical path for digest, as an operator-seeded offline cache would.
func seedCache(t *testing.T, root, digest string, b []byte) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(digest, "sha512:"))
	if err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(raw)
	dir := filepath.Join(root, "sha512", h[:2])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, h), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDependencyAcquisitionOutcomes(t *testing.T) {
	tarball := []byte("qs tarball bytes")
	other := []byte("not the pinned bytes")
	qs := "pkg:npm/qs@6.5.2"

	tests := []struct {
		name     string
		mode     DependencyCodeMode
		npmrc    string
		env      map[string]string
		served   []byte
		seed     []byte
		digest   string
		registry string // registry host the .npmrc names; "" is registry.test
		status   int    // non-zero: registry.test answers every request with this status
		timeout  time.Duration
		wantRead int
		want     string // Unread reason, "" when read
		detail   string
		wantReqs int
	}{
		{name: "fetch verifies and reads", mode: DependencyCodeFetch, served: tarball, digest: sri512(tarball), wantRead: 1, wantReqs: 1},
		{name: "fetch sri mismatch", mode: DependencyCodeFetch, served: other, digest: sri512(tarball), want: UnreadIntegrityMismatch, wantReqs: 1},
		{name: "no lock integrity", mode: DependencyCodeFetch, served: tarball, digest: "", want: UnreadNoIntegrity},
		{name: "malformed lock integrity", mode: DependencyCodeFetch, served: tarball, digest: "sha512:short", want: UnreadMalformedIntegrity},
		{name: "fetch verifies a sha1-only lock entry", mode: DependencyCodeFetch, served: tarball, digest: sri1(tarball), wantRead: 1, wantReqs: 1},
		{name: "malformed npmrc fails closed", mode: DependencyCodeFetch, npmrc: "//registry.test/:_authToken=${NPM_TOKEN}", served: tarball, digest: sri512(tarball), want: UnreadNPMRCMalformed, detail: `project .npmrc line 2: references unset environment variable "NPM_TOKEN"`},
		{name: "repository reference to GITHUB_TOKEN fails closed", mode: DependencyCodeFetch, npmrc: "//registry.test/:_authToken=${GITHUB_TOKEN}", env: map[string]string{"GITHUB_TOKEN": acqSecret}, served: tarball, digest: sri512(tarball), want: UnreadNPMRCMalformed},
		{name: "registry does not serve the tarball", mode: DependencyCodeFetch, digest: sri512(tarball), want: UnreadNotServed, wantReqs: 1},
		{name: "empty per-host token refuses before any request", mode: DependencyCodeFetch, npmrc: "//registry.test/:_authToken=", served: tarball, digest: sri512(tarball), want: UnreadPolicyRefused, detail: "missing-credential"},
		{name: "top-level auth refuses before any request", mode: DependencyCodeFetch, npmrc: "_auth=Zm9vOmJhcg==", served: tarball, digest: sri512(tarball), want: UnreadPolicyRefused, detail: "missing-credential"},
		{name: "public registry reads with an optional token unset", mode: DependencyCodeFetch, npmrc: "//registry.test/:_authToken=${NPM_TOKEN?}", served: tarball, digest: sri512(tarball), wantRead: 1, wantReqs: 1},
		{name: "401 where an optional token is unset", mode: DependencyCodeFetch, npmrc: "//registry.test/:_authToken=${NPM_TOKEN?}", status: http.StatusUnauthorized, digest: sri512(tarball), want: UnreadPolicyRefused, detail: "missing-credential", wantReqs: 1},
		{name: "403 where an optional token is unset", mode: DependencyCodeFetch, npmrc: "//registry.test/:_authToken=${NPM_TOKEN?}", status: http.StatusForbidden, digest: sri512(tarball), want: UnreadPolicyRefused, detail: "missing-credential", wantReqs: 1},
		{name: "401 refusing a presented token", mode: DependencyCodeFetch, npmrc: "//registry.test/:_authToken=${NPM_TOKEN}", env: map[string]string{"NPM_TOKEN": acqSecret}, status: http.StatusUnauthorized, digest: sri512(tarball), want: UnreadPolicyRefused, detail: "credential-rejected", wantReqs: 1},
		{name: "403 refusing a presented token", mode: DependencyCodeFetch, npmrc: "//registry.test/:_authToken=${NPM_TOKEN}", env: map[string]string{"NPM_TOKEN": acqSecret}, status: http.StatusForbidden, digest: sri512(tarball), want: UnreadPolicyRefused, detail: "credential-rejected", wantReqs: 1},
		{name: "401 with no auth configured", mode: DependencyCodeFetch, status: http.StatusUnauthorized, digest: sri512(tarball), want: UnreadNotServed, wantReqs: 1},
		{name: "transport failure", mode: DependencyCodeFetch, registry: "down.test", served: tarball, digest: sri512(tarball), want: UnreadFetchFailed},
		{name: "stage deadline passes", mode: DependencyCodeFetch, timeout: time.Nanosecond, served: tarball, digest: sri512(tarball), want: UnreadCancelled},
		{name: "offline empty cache", mode: DependencyCodeOffline, served: tarball, digest: sri512(tarball), want: UnreadNotCached},
		{name: "offline seeded cache", mode: DependencyCodeOffline, served: tarball, seed: tarball, digest: sri512(tarball), wantRead: 1},
		{name: "offline tampered cache", mode: DependencyCodeOffline, served: tarball, seed: other, digest: sri512(tarball), want: UnreadIntegrityMismatch},
		{name: "fetch over tampered cache entry", mode: DependencyCodeFetch, served: tarball, seed: other, digest: sri512(tarball), want: UnreadIntegrityMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regs := newFakeRegistries()
			regs.serveStatus(t, "registry.test", tt.status, tt.served)
			build, cache := t.TempDir(), t.TempDir()
			registry := tt.registry
			if registry == "" {
				registry = "registry.test"
			}
			npmrc := "registry=https://" + registry + "/\n" + tt.npmrc
			if err := os.WriteFile(filepath.Join(build, ".npmrc"), []byte(npmrc), 0o600); err != nil {
				t.Fatal(err)
			}
			if tt.seed != nil {
				seedCache(t, cache, tt.digest, tt.seed)
			}
			d := &dependencyAcquirer{
				cfg:   DependencyAcquisition{Mode: tt.mode, CacheDir: cache, LookupEnv: envMap(tt.env), Timeout: tt.timeout, Client: regs.client},
				byDir: map[string]*acquiredBuild{},
			}
			res := d.result(context.Background(), build, build, inventoryPlugin{nodes: []plugin.DependencyNode{npmNode(qs, tt.digest)}})
			if res.Read != tt.wantRead {
				t.Fatalf("Read = %d, want %d (unread %+v)", res.Read, tt.wantRead, res.Unread)
			}
			got, detail := "", ""
			if len(res.Unread) == 1 {
				got, detail = res.Unread[0].Reason, res.Unread[0].Detail
			}
			if got != tt.want {
				t.Fatalf("unread reason = %q, want %q", got, tt.want)
			}
			if tt.detail != "" && detail != tt.detail {
				t.Fatalf("unread detail = %q, want %q", detail, tt.detail)
			}
			if strings.Contains(detail, acqSecret) {
				t.Fatal("unread detail carries the token")
			}
			seen := regs.seen("registry.test")
			if n := len(seen); n != tt.wantReqs {
				t.Fatalf("registry requests = %d, want %d", n, tt.wantReqs)
			}
			if len(tt.env) == 0 {
				for _, a := range seen {
					if a != "" {
						t.Fatalf("anonymous fetch carried Authorization %q", a)
					}
				}
			}
		})
	}
}

// A concrete finding keeps its reason after the deadline; only an error the deadline could have
// caused reads as cancelled.
func TestClassifyAcquireErrorAfterDeadline(t *testing.T) {
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "integrity mismatch", err: fmt.Errorf("verify: %w", artifactcache.ErrIntegrityMismatch), want: UnreadIntegrityMismatch},
		{name: "policy refusal", err: &artifactcache.PolicyReason{Code: artifactcache.PolicyMissingCredential}, want: UnreadPolicyRefused},
		{name: "malformed pin", err: artifactcache.ErrMalformedRef, want: UnreadMalformedIntegrity},
		{name: "not served", err: artifactcache.ErrDeclaredAbsent, want: UnreadCancelled},
		{name: "transport", err: context.DeadlineExceeded, want: UnreadCancelled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyAcquireError(expired, "pkg:npm/qs@6.5.2", tt.err).Reason; got != tt.want {
				t.Fatalf("reason = %q, want %q", got, tt.want)
			}
		})
	}
}

// slowInventoryPlugin's inventory outlasts any deadline; failingInventoryPlugin's fails at once.
type slowInventoryPlugin struct{ inventoryPlugin }

func (slowInventoryPlugin) ResolveInventory(ctx context.Context, _ plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	<-ctx.Done()
	return plugin.DependencyInventory{}, ctx.Err()
}

type failingInventoryPlugin struct{ inventoryPlugin }

func (failingInventoryPlugin) ResolveInventory(context.Context, plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return plugin.DependencyInventory{}, errors.New("lock unreadable")
}

// An inventory cut off by the stage deadline enumerates nothing: it records the run-wide
// tool_failure, marked cancelled so it is not read as a plugin defect.
func TestDependencyAcquisitionInventoryDeadline(t *testing.T) {
	tests := []struct {
		name          string
		plugin        plugin.LanguagePlugin
		wantCancelled bool
	}{
		{name: "inventory outlasts the deadline", plugin: slowInventoryPlugin{}, wantCancelled: true},
		{name: "inventory fails", plugin: failingInventoryPlugin{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			build := t.TempDir()
			d := &dependencyAcquirer{
				cfg:   DependencyAcquisition{Mode: DependencyCodeOffline, CacheDir: t.TempDir(), Timeout: 10 * time.Millisecond},
				byDir: map[string]*acquiredBuild{},
			}
			res := d.result(context.Background(), build, build, tt.plugin)
			if len(res.InventoryPartial) != 1 || res.InventoryPartial[0] != plugin.PartialReasonToolFailure {
				t.Fatalf("InventoryPartial = %v, want [%s]", res.InventoryPartial, plugin.PartialReasonToolFailure)
			}
			if res.InventoryCancelled != tt.wantCancelled {
				t.Fatalf("InventoryCancelled = %v, want %v", res.InventoryCancelled, tt.wantCancelled)
			}
			if res.Read != 0 || len(res.Unread) != 0 {
				t.Fatalf("read %d unread %v from an inventory that enumerated nothing", res.Read, res.Unread)
			}
		})
	}
}

// A build dir reached through a directory symlink that leaves the checkout must not make the
// target directory's .npmrc the project layer.
func TestDependencyAcquisitionContainsBuildDir(t *testing.T) {
	tarball := []byte("qs tarball bytes")
	regs := newFakeRegistries()
	regs.serve(t, "registry.test", tarball)
	regs.serve(t, "home.test", tarball)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, ".npmrc"), []byte("registry=https://home.test/\n//home.test/:_authToken=${NODE_AUTH_TOKEN}"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkout := t.TempDir()
	if err := os.WriteFile(filepath.Join(checkout, ".npmrc"), []byte("registry=https://registry.test/"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(checkout, "app")
	if err := os.Symlink(outside, linked); err != nil {
		t.Fatal(err)
	}
	d := &dependencyAcquirer{
		cfg: DependencyAcquisition{Mode: DependencyCodeFetch, CacheDir: t.TempDir(), Client: regs.client,
			LookupEnv: envMap(map[string]string{"NODE_AUTH_TOKEN": acqSecret})},
		byDir: map[string]*acquiredBuild{},
	}
	res := d.result(context.Background(), linked, checkout, inventoryPlugin{nodes: []plugin.DependencyNode{npmNode("pkg:npm/qs@6.5.2", sri512(tarball))}})
	if res.Read != 0 || len(res.Unread) != 1 || res.Unread[0].Reason != UnreadNPMRCMalformed {
		t.Fatalf("read %d unread %+v, want one npmrc_malformed", res.Read, res.Unread)
	}
	if strings.Contains(res.Unread[0].Detail, acqSecret) {
		t.Fatal("unread detail carries the token")
	}
	if n := len(regs.seen("home.test")); n != 0 {
		t.Fatalf("the out-of-checkout registry saw %d requests", n)
	}
}

func envMap(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// A token bound to host A is presented to A and never to B, and a token in $HOME/.npmrc is
// never read.
func TestDependencyAcquisitionTokenIsolation(t *testing.T) {
	a, b := []byte("scoped tarball"), []byte("public tarball")
	regs := newFakeRegistries()
	regs.serve(t, "npm.a.test", a)
	regs.serve(t, "registry.b.test", b)

	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".npmrc"), []byte("//registry.b.test/:_authToken=home-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	build := t.TempDir()
	npmrc := strings.Join([]string{
		"registry=https://registry.b.test/",
		"@a:registry=https://npm.a.test/",
		"//npm.a.test/:_authToken=${NODE_AUTH_TOKEN}",
	}, "\n")
	if err := os.WriteFile(filepath.Join(build, ".npmrc"), []byte(npmrc), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &dependencyAcquirer{
		cfg: DependencyAcquisition{Mode: DependencyCodeFetch, CacheDir: t.TempDir(), Client: regs.client,
			LookupEnv: envMap(map[string]string{"NODE_AUTH_TOKEN": acqSecret, "HOME": home})},
		byDir: map[string]*acquiredBuild{},
	}
	res := d.result(context.Background(), build, build, inventoryPlugin{nodes: []plugin.DependencyNode{
		npmNode("pkg:npm/%40a/lib@1.0.0", sri512(a)),
		npmNode("pkg:npm/qs@6.5.2", sri512(b)),
	}})
	if res.Read != 2 {
		t.Fatalf("Read = %d, unread %+v", res.Read, res.Unread)
	}
	if got := regs.seen("npm.a.test"); len(got) != 1 || got[0] != "Bearer "+acqSecret {
		t.Fatalf("host A saw %q, want its own token", got)
	}
	if got := regs.seen("registry.b.test"); len(got) != 1 || got[0] != "" {
		t.Fatalf("host B saw Authorization %q, want none", got)
	}
}

// The token reaches no artifact payload and no file the cache holds.
func TestDependencyAcquisitionTokenNotRecorded(t *testing.T) {
	ok, bad := []byte("good tarball"), []byte("bad tarball")
	regs := newFakeRegistries()
	regs.serve(t, "npm.a.test", ok)
	regs.serve(t, "registry.test", bad)
	build, cache := t.TempDir(), t.TempDir()
	npmrc := strings.Join([]string{
		"registry=https://registry.test/",
		"//registry.test/:_authToken=${CORP_TOKEN}",
		"@a:registry=https://npm.a.test/",
		"//npm.a.test/:_authToken=${CORP_TOKEN}",
	}, "\n")
	if err := os.WriteFile(filepath.Join(build, ".npmrc"), []byte(npmrc), 0o600); err != nil {
		t.Fatal(err)
	}
	p := inventoryPlugin{nodes: []plugin.DependencyNode{
		npmNode("pkg:npm/%40a/lib@1.0.0", sri512(ok)),
		npmNode("pkg:npm/qs@6.5.2", sri512(ok)), // served bytes mismatch: an unread outcome is recorded too
	}}

	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-1"}
	if _, err := PutArtifact(store, c, "codebase_inventory", artifact.TypeInventory, "", map[string]string{"build_dir": build, "language": "js"}); err != nil {
		t.Fatal(err)
	}
	stage := dependencyAcquisition{plugin: p, acq: &dependencyAcquirer{
		cfg:   DependencyAcquisition{Mode: DependencyCodeFetch, CacheDir: cache, Client: regs.client, LookupEnv: envMap(map[string]string{"CORP_TOKEN": acqSecret}), AllowEnv: []string{"CORP_TOKEN"}},
		byDir: map[string]*acquiredBuild{},
	}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		if strings.Contains(err.Error(), acqSecret) {
			t.Fatal("stage error carries the token")
		}
		t.Fatal(err)
	}
	res, ran := DependencyAcquisitionOf(store, c.ID)
	if !ran || res.Read != 1 || len(res.Unread) != 1 || res.Unread[0].Reason != UnreadIntegrityMismatch {
		t.Fatalf("result = %+v (ran %v)", res, ran)
	}
	for _, typ := range []artifact.Type{artifact.TypeInventory, TypeDependencyAcquisition} {
		arts, err := store.Query(c.ID, typ)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range arts {
			if strings.Contains(string(a.Payload), acqSecret) {
				t.Fatalf("%s artifact carries the token", typ)
			}
		}
	}
	err := filepath.WalkDir(cache, func(path string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), acqSecret) {
			t.Errorf("cache file %s carries the token", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), "registry.test") || strings.Contains(string(raw), "npm.a.test") {
		t.Fatalf("result names a registry host: %s", raw)
	}
}

// goInventoryPlugin is inventoryPlugin claiming the Go lane.
type goInventoryPlugin struct{ inventoryPlugin }

func (goInventoryPlugin) Language() string { return "go" }

// A non-JS build gets no dependency_acquisition artifact, whichever plugin the stage holds.
func TestDependencyAcquisitionSkipsNonJS(t *testing.T) {
	for _, p := range []plugin.LanguagePlugin{inventoryPlugin{}, goInventoryPlugin{}} {
		t.Run(p.Language()+" plugin", func(t *testing.T) {
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-go"}
			if _, err := PutArtifact(store, c, "codebase_inventory", artifact.TypeInventory, "", map[string]string{"build_dir": t.TempDir(), "language": "go"}); err != nil {
				t.Fatal(err)
			}
			stage := dependencyAcquisition{plugin: p, acq: &dependencyAcquirer{
				cfg:   DependencyAcquisition{Mode: DependencyCodeOffline, CacheDir: t.TempDir()},
				byDir: map[string]*acquiredBuild{},
			}}
			if err := stage.Run(context.Background(), c, store); err != nil {
				t.Fatal(err)
			}
			if _, ran := DependencyAcquisitionOf(store, c.ID); ran {
				t.Fatal("dependency_acquisition recorded a result for a Go build")
			}
		})
	}
}

// The stage is absent unless the option is set, so a default run is unchanged.
func TestDependencyAcquisitionStageOptIn(t *testing.T) {
	has := func(stages []Stage) bool {
		for _, s := range stages {
			if s.Name() == "dependency_acquisition" {
				return true
			}
		}
		return false
	}
	if has(AssessStages()) {
		t.Fatal("dependency_acquisition runs without WithDependencyAcquisition")
	}
	stages := AssessStages(WithDependencyAcquisition(DependencyAcquisition{Mode: DependencyCodeOffline, CacheDir: t.TempDir()}))
	if !has(stages) {
		t.Fatal("WithDependencyAcquisition did not add the stage")
	}
	var names []string
	for _, s := range stages {
		names = append(names, s.Name())
	}
	if got := strings.Join(names, ","); !strings.Contains(got, "disqualification_discovery,dependency_acquisition,symbol_mapping") {
		t.Fatalf("stage order %s", got)
	}
}
