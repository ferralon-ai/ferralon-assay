package pipeline

import (
	"context"
	"crypto/sha1" //nolint:gosec // lock SRI fixture
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.requests[host] = append(r.requests[host], req.Header.Get("Authorization"))
		r.mu.Unlock()
		if body == nil {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(body)
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
			regs.serve(t, "registry.test", tt.served)
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
			res := d.result(context.Background(), build, inventoryPlugin{nodes: []plugin.DependencyNode{npmNode(qs, tt.digest)}})
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
			if n := len(regs.seen("registry.test")); n != tt.wantReqs {
				t.Fatalf("registry requests = %d, want %d", n, tt.wantReqs)
			}
		})
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
	res := d.result(context.Background(), build, inventoryPlugin{nodes: []plugin.DependencyNode{
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

// A non-JS build gets no dependency_acquisition artifact and no inventory call.
func TestDependencyAcquisitionSkipsNonJS(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-go"}
	if _, err := PutArtifact(store, c, "codebase_inventory", artifact.TypeInventory, "", map[string]string{"build_dir": t.TempDir(), "language": "go"}); err != nil {
		t.Fatal(err)
	}
	stage := dependencyAcquisition{plugin: inventoryPlugin{}, acq: &dependencyAcquirer{
		cfg:   DependencyAcquisition{Mode: DependencyCodeOffline, CacheDir: t.TempDir()},
		byDir: map[string]*acquiredBuild{},
	}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatal(err)
	}
	if _, ran := DependencyAcquisitionOf(store, c.ID); ran {
		t.Fatal("dependency_acquisition recorded a result for a Go build")
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
