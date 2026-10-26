package jsanalysis

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depPkg is one lock entry of a dependency fixture and the files its tarball carries.
type depPkg struct {
	path, name, version string
	files               map[string]string
	lockInstallScript   bool
	tgz                 []byte
}

// buildTgz packs files under npm's "package/" top directory.
func buildTgz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sri(b []byte) string {
	sum := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// depFixture is a first-party program plus an npm v3 lock pinning pkgs.
type depFixture struct {
	dir  string
	pkgs []*depPkg
}

func newDepFixture(t *testing.T, firstParty map[string]string, pkgs ...*depPkg) *depFixture {
	t.Helper()
	lockPkgs := map[string]any{"": map[string]any{"name": "app", "version": "1.0.0"}}
	for _, p := range pkgs {
		if p.tgz == nil {
			p.tgz = buildTgz(t, p.files)
		}
		entry := map[string]any{
			"version":   p.version,
			"resolved":  "https://registry.npmjs.org/" + p.name + "/-/" + p.name + "-" + p.version + ".tgz",
			"integrity": sri(p.tgz),
		}
		if p.lockInstallScript {
			entry["hasInstallScript"] = true
		}
		lockPkgs[p.path] = entry
	}
	lock, err := json.Marshal(map[string]any{"name": "app", "lockfileVersion": 3, "requires": true, "packages": lockPkgs})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"package-lock.json": string(lock)}
	if _, ok := firstParty["package.json"]; !ok {
		files["package.json"] = `{"name":"app","version":"1.0.0"}`
	}
	for k, v := range firstParty {
		files[k] = v
	}
	return &depFixture{dir: writeProgram(t, files), pkgs: pkgs}
}

func (f *depFixture) ref(p *depPkg) artifactcache.Ref {
	return artifactcache.Ref{PURL: makePURL(p.name, p.version), Digest: mapIntegrity(sri(p.tgz))}
}

// memStore holds every fixture tarball under its lock ref.
func (f *depFixture) memStore() artifactcache.Store {
	m := map[artifactcache.Ref][]byte{}
	for _, p := range f.pkgs {
		m[f.ref(p)] = p.tgz
	}
	return artifactcache.NewMemStore(m)
}

// diskCache publishes every fixture tarball at its canonical path and returns the cache root.
func (f *depFixture) diskCache(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, p := range f.pkgs {
		dst, err := artifactcache.CanonicalPath(root, f.ref(p).Digest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, p.tgz, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func withDeps(t *testing.T, dir string, store artifactcache.Store) plugin.CallGraphResult {
	t.Helper()
	res, _, err := callGraphWithDeps(context.Background(), dir, store, time.Minute)
	if err != nil {
		t.Fatalf("callGraphWithDeps: %v", err)
	}
	return res
}

// hasScoped reports whether p carries an unbounded scoped limit attributed to pkg: the limit of
// a package whose code is hidden, which may load any installed package.
func hasScoped(p plugin.Partiality, reason, pkg string) bool {
	for _, s := range p.Scoped {
		if s.Reason == reason && s.Package == pkg && len(s.Targets) == 0 {
			return true
		}
	}
	return false
}

// The body-parser stand-in: its urlencoded parser calls qs.parse.
func bodyParserPkg(at string, deps string) *depPkg {
	return &depPkg{
		path: at, name: "body-parser", version: "1.19.0",
		files: map[string]string{
			"package.json":        `{"name":"body-parser","version":"1.19.0","main":"index.js","dependencies":{"qs":"` + deps + `"}}`,
			"index.js":            "const urlencoded = require('./lib/urlencoded');\nexports.urlencoded = urlencoded;\n",
			"lib/urlencoded.js":   "const qs = require('qs');\nfunction urlencoded(opts) {\n  return function parser(req, res, next) { req.body = qs.parse(req.raw, opts); next(); };\n}\nmodule.exports = urlencoded;\n",
			"lib/urlencoded.d.ts": "export {};\n",
		},
	}
}

func qsPkg(at, version string) *depPkg {
	return &depPkg{
		path: at, name: "qs", version: version,
		files: map[string]string{
			"package.json": `{"name":"qs","version":"` + version + `","main":"lib/index.js"}`,
			"lib/index.js": "const parse = require('./parse');\nmodule.exports = { parse };\n",
			"lib/parse.js": "module.exports = function parse(str, opts) { return {}; };\n",
		},
	}
}

const bodyParserApp = `const express = require('express');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.post('/', (req, res) => res.send(req.body));
app.listen(3000);
`

// TestDepGraph_QsViaBodyParser (H/M 1): an app that only names body-parser reaches qs.parse
// through body-parser's own code. Without the dependency cache the advisory resolves to
// nothing and the verdict is withheld; with it, the lock-pinned copy's boundary node
// resolves and has a path.
func TestDepGraph_QsViaBodyParser(t *testing.T) {
	ctx := context.Background()
	f := newDepFixture(t, map[string]string{"index.js": bodyParserApp},
		bodyParserPkg("node_modules/body-parser", "6.7.0"),
		qsPkg("node_modules/qs", "6.7.0"),
	)
	cache := f.diskCache(t)
	const purl = "pkg:npm/qs@6.7.0"
	const sink = "npm:qs@6.7.0#parse"
	req := plugin.ResolveSymbolsRequest{BuildDir: f.dir, PURL: purl, Package: purl, AdvisorySymbols: []string{"qs.parse"}}

	if got := resolvedSCIPs(mustResolve(t, req)); len(got) != 0 {
		t.Fatalf("without dependency code qs.parse must stay unresolved; got %v", got)
	}

	req.DependencyCache = cache
	res := mustResolve(t, req)
	if got := resolvedSCIPs(res); !slices.Equal(got, []string{sink}) {
		t.Fatalf("resolved = %v, want [%s]", got, sink)
	}
	if res.Origins[sink] != "pkg:npm/qs" {
		t.Errorf("origin = %q, want pkg:npm/qs", res.Origins[sink])
	}
	reach, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: f.dir, Symbols: []string{sink}, DependencyCache: cache})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(reach.Paths) != 1 {
		t.Fatalf("want a path to %s, got %+v", sink, reach.Paths)
	}
	trace := reach.Paths[0].Trace
	if trace[len(trace)-1].SCIP != sink {
		t.Errorf("trace ends at %s, want %s", trace[len(trace)-1].SCIP, sink)
	}
	if !slices.ContainsFunc(trace, func(s plugin.Symbol) bool {
		return strings.HasPrefix(s.SCIP, scipManager+" body-parser 1.19.0 lib/urlencoded/")
	}) {
		t.Errorf("the path must run through body-parser's urlencoded under its npm coordinate; trace %+v", trace)
	}
}

func mustResolve(t *testing.T, req plugin.ResolveSymbolsRequest) plugin.SymbolResolutionResult {
	t.Helper()
	res, err := ResolveDependencySymbols(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	return res
}

// TestDepGraph_OnlyTheOnPathCopy (H/M 2): body-parser loads its nested qs@6.7.0; the hoisted
// qs@6.5.0 is used only by a package nothing loads. Only the nested copy resolves.
func TestDepGraph_OnlyTheOnPathCopy(t *testing.T) {
	request := &depPkg{
		path: "node_modules/request", name: "request", version: "2.88.0",
		files: map[string]string{
			"package.json": `{"name":"request","version":"2.88.0","main":"index.js"}`,
			"index.js":     "const qs = require('qs');\nmodule.exports = function request(u) { return qs.parse(u); };\n",
		},
	}
	f := newDepFixture(t, map[string]string{"index.js": bodyParserApp},
		bodyParserPkg("node_modules/body-parser", "6.7.0"),
		qsPkg("node_modules/body-parser/node_modules/qs", "6.7.0"),
		qsPkg("node_modules/qs", "6.5.0"),
		request,
	)
	cache := f.diskCache(t)
	for _, tc := range []struct {
		version string
		want    []string
	}{
		{"6.7.0", []string{"npm:qs@6.7.0#parse"}},
		{"6.5.0", nil},
	} {
		purl := "pkg:npm/qs@" + tc.version
		res := mustResolve(t, plugin.ResolveSymbolsRequest{BuildDir: f.dir, PURL: purl, Package: purl, AdvisorySymbols: []string{"qs.parse"}, DependencyCache: cache})
		if got := resolvedSCIPs(res); !slices.Equal(got, tc.want) {
			t.Errorf("%s: resolved = %v, want %v", purl, got, tc.want)
		}
	}
	// Copies that disagree leave Package unversioned; the host lists the installed versions the
	// advisory's ranges do not rule out, and only an on-path copy at one of them resolves.
	for _, tc := range []struct {
		versions []string
		want     []string
	}{
		{[]string{"6.5.0", "6.7.0"}, []string{"npm:qs@6.7.0#parse"}},
		{[]string{"6.5.0"}, nil},
		{nil, nil},
	} {
		res := mustResolve(t, plugin.ResolveSymbolsRequest{BuildDir: f.dir, PURL: "pkg:npm/qs", PackageVersions: tc.versions, AdvisorySymbols: []string{"qs.parse"}, DependencyCache: cache})
		if got := resolvedSCIPs(res); !slices.Equal(got, tc.want) {
			t.Errorf("versions %v: resolved = %v, want %v", tc.versions, got, tc.want)
		}
	}
}

// TestDepGraph_Controls: every way dependency code goes unread or carries a limit keeps the
// matching partiality, scoped to the package where the design scopes it and run-wide
// otherwise.
func TestDepGraph_Controls(t *testing.T) {
	const app = "const dep = require('dep');\ndep.run();\n"
	// A first-party load of any package already declares uninspectable_package run-wide, so the
	// rows that tell run-wide from scoped use a program that loads nothing. An install script
	// runs whether or not anything loads its package.
	const idle = "module.exports = 1;\n"
	plain := func(files map[string]string) *depPkg {
		m := map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"index.js"}`, "index.js": "exports.run = function run() {};\n"}
		for k, v := range files {
			m[k] = v
		}
		return &depPkg{path: "node_modules/dep", name: "dep", version: "1.0.0", files: m}
	}
	const purl = "pkg:npm/dep@1.0.0"

	t.Run("sri_mismatch_scopes_the_package", func(t *testing.T) {
		p := plain(nil)
		f := newDepFixture(t, map[string]string{"index.js": app}, p)
		tampered := artifactcache.NewMemStore(map[artifactcache.Ref][]byte{f.ref(p): buildTgz(t, map[string]string{"package.json": `{"name":"dep"}`, "index.js": "exports.run = function run() { evil(); };\n"})})
		cg := withDeps(t, f.dir, tampered)
		if !hasScoped(cg.Partiality, plugin.PartialReasonUninspectablePackage, purl) {
			t.Errorf("an integrity mismatch must leave dep unread with a scoped limit; got %+v", cg.Partiality)
		}
		if slices.ContainsFunc(cg.Edges, func(e plugin.CallEdge) bool {
			return strings.Contains(e.Callee.SCIP, "evil") || strings.Contains(e.Callee.SCIP, " dep 1.0.0 ")
		}) {
			t.Errorf("tampered bytes must never be parsed; edges %+v", cg.Edges)
		}
	})

	t.Run("offline_empty_cache", func(t *testing.T) {
		f := newDepFixture(t, map[string]string{"index.js": app}, plain(nil))
		cg := withDeps(t, f.dir, artifactcache.NewDeclaredAbsentStore())
		if !hasScoped(cg.Partiality, plugin.PartialReasonUninspectablePackage, purl) {
			t.Errorf("a cache miss must scope dep uninspectable; got %+v", cg.Partiality)
		}
		if cg.Partiality.Complete {
			t.Error("missing code never completes a graph")
		}
	})

	t.Run("yarn_berry_withholds_run_wide", func(t *testing.T) {
		dir := writeProgram(t, map[string]string{
			"package.json": `{"name":"app","version":"1.0.0","dependencies":{"dep":"1.0.0"}}`,
			"yarn.lock":    "__metadata:\n  version: 6\n\n\"dep@npm:1.0.0\":\n  version: 1.0.0\n  resolution: \"dep@npm:1.0.0\"\n",
			"index.js":     idle,
		})
		cg := withDeps(t, dir, artifactcache.NewDeclaredAbsentStore())
		if !hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage) {
			t.Errorf("a yarn berry lock must withhold run-wide; got %+v", cg.Partiality)
		}
	})

	t.Run("install_script_run_wide", func(t *testing.T) {
		f := newDepFixture(t, map[string]string{"index.js": idle}, plain(map[string]string{
			"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","scripts":{"postinstall":"node setup.js"}}`,
		}))
		clean := newDepFixture(t, map[string]string{"index.js": idle}, plain(nil))
		if cg := withDeps(t, clean.dir, clean.memStore()); hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage) {
			t.Fatalf("control: a read package without an install script adds no run-wide limit; got %+v", cg.Partiality)
		}
		if cg := withDeps(t, f.dir, f.memStore()); !hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage) {
			t.Errorf("an install script must withhold run-wide; got %+v", cg.Partiality)
		}
	})

	t.Run("lock_install_script_on_unread_package_run_wide", func(t *testing.T) {
		p := plain(nil)
		p.lockInstallScript = true
		f := newDepFixture(t, map[string]string{"index.js": idle}, p)
		if cg := withDeps(t, f.dir, artifactcache.NewDeclaredAbsentStore()); !hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage) {
			t.Errorf("an unread package the lock marks hasInstallScript must withhold run-wide; got %+v", cg.Partiality)
		}
	})

	t.Run("native_addon_scoped", func(t *testing.T) {
		f := newDepFixture(t, map[string]string{"index.js": idle}, plain(map[string]string{"build/Release/dep.node": "\x7fELF"}))
		cg := withDeps(t, f.dir, f.memStore())
		if !hasScoped(cg.Partiality, plugin.PartialReasonUninspectablePackage, purl) {
			t.Errorf("a native addon must scope its package; got %+v", cg.Partiality)
		}
		if hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage) {
			t.Errorf("a native addon without an install script stays scoped; got %+v", cg.Partiality)
		}
	})

	t.Run("dependency_computed_require_run_wide", func(t *testing.T) {
		f := newDepFixture(t, map[string]string{"index.js": "require('dep');\n"}, plain(map[string]string{
			"index.js": "const name = process.env.PLUGIN;\nexports.run = function run() { return require(name); };\n",
		}))
		if cg := withDeps(t, f.dir, f.memStore()); !hasReason(cg.Partiality, plugin.PartialReasonComputedRequireSpecifier) {
			t.Errorf("require(variable) in dependency code must stay run-wide; got %+v", cg.Partiality)
		}
	})

	t.Run("budget_overrun_scopes_unread_packages", func(t *testing.T) {
		f := newDepFixture(t, map[string]string{"index.js": app}, plain(nil))
		res, _, err := callGraphWithDeps(context.Background(), f.dir, f.memStore(), 0)
		if err != nil {
			t.Fatalf("a spent budget is a limit, not an error: %v", err)
		}
		if !hasScoped(res.Partiality, plugin.PartialReasonToolFailure, purl) {
			t.Errorf("a package the budget left unread must carry a scoped tool_failure; got %+v", res.Partiality)
		}
	})

	t.Run("outer_cancel_is_an_error", func(t *testing.T) {
		f := newDepFixture(t, map[string]string{"index.js": app}, plain(nil))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := callGraphWithDeps(ctx, f.dir, f.memStore(), time.Minute); err == nil {
			t.Error("a cancelled run must error, never return a partial graph")
		}
	})
}

// TestDepGraph_FirstPartyByteIdentical: with no dependency code to read, the graph is
// byte-for-byte the first-party graph.
func TestDepGraph_FirstPartyByteIdentical(t *testing.T) {
	programs := []map[string]string{
		{"index.js": fixtureB, "package.json": `{"name":"app","version":"1.0.0"}`},
		{"index.js": "const { f } = require('./lib');\nf();\n", "lib.js": "exports.f = function f() { eval('1'); };\n"},
		{"index.js": "const { g } = require('./lib');\ng();\n", "lib.js": "exports.g = function g() { return 1; };\n", "package.json": `{"name":"app","version":"1.0.0"}`},
		{"src/a.ts": "import { b } from './b';\nexport function a() { return b(); }\n", "src/b.ts": "export function b() { return 1; }\n", "tsconfig.json": "{}"},
	}
	for i, files := range programs {
		dir := writeProgram(t, files)
		base, _, err := callGraphInternal(dir)
		if err != nil {
			t.Fatal(err)
		}
		head := withDeps(t, dir, artifactcache.NewDeclaredAbsentStore())
		bj, _ := json.Marshal(base)
		hj, _ := json.Marshal(head)
		if !bytes.Equal(bj, hj) {
			t.Errorf("program %d: graph changed\nbase %s\nhead %s", i, bj, hj)
		}
	}
}

// TestDepGraph_NoNewNotExploitable: reading dependency code only adds edges and limits, so a
// verdict that was not refuted at main can never become refuted at head.
func TestDepGraph_NoNewNotExploitable(t *testing.T) {
	plainDep := &depPkg{path: "node_modules/dep", name: "dep", version: "1.0.0", files: map[string]string{
		"package.json": `{"name":"dep","version":"1.0.0"}`, "index.js": "exports.run = function run() {};\n",
	}}
	fixtures := []*depFixture{
		newDepFixture(t, map[string]string{"index.js": bodyParserApp}, bodyParserPkg("node_modules/body-parser", "6.7.0"), qsPkg("node_modules/qs", "6.7.0")),
		newDepFixture(t, map[string]string{"index.js": bodyParserApp}, bodyParserPkg("node_modules/body-parser", "6.7.0"), qsPkg("node_modules/body-parser/node_modules/qs", "6.7.0"), qsPkg("node_modules/qs", "6.5.0")),
		newDepFixture(t, map[string]string{"index.js": "require('dep').run();\n"}, plainDep),
	}
	for i, f := range fixtures {
		base, _, err := callGraphInternal(f.dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, store := range []artifactcache.Store{f.memStore(), artifactcache.NewDeclaredAbsentStore()} {
			head := withDeps(t, f.dir, store)
			if head.Partiality.Complete && !base.Partiality.Complete {
				t.Errorf("fixture %d: head completed a graph main left partial", i)
			}
			for _, r := range base.Partiality.Reasons {
				if !hasReason(head.Partiality, r) {
					t.Errorf("fixture %d: head dropped limit %s", i, r)
				}
			}
			for _, e := range base.Edges {
				if !hasEdge(head.Edges, e.Caller.SCIP, e.Callee.SCIP) {
					t.Errorf("fixture %d: head dropped edge %s -> %s", i, e.Caller.SCIP, e.Callee.SCIP)
				}
			}
		}
	}
}

// TestDepGraph_NoTokenInRecords: an auth token in the build's .npmrc and environment never
// reaches the graph or the run cache; the lane reads only the store it is handed.
func TestDepGraph_NoTokenInRecords(t *testing.T) {
	const token = "npm_SECRETTOKEN0123456789abcdef"
	t.Setenv("NPM_TOKEN", token)
	f := newDepFixture(t, map[string]string{
		"index.js": bodyParserApp,
		".npmrc":   "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n//registry.example.test/:_authToken=" + token + "\n",
	}, bodyParserPkg("node_modules/body-parser", "6.7.0"), qsPkg("node_modules/qs", "6.7.0"))
	runDir := t.TempDir()
	ctx := WithRunCacheDir(context.Background(), runDir)
	cg, err := callGraphFor(ctx, f.dir, f.diskCache(t))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cg)
	if bytes.Contains(b, []byte(token)) {
		t.Error("token present in the call graph")
	}
	entries, err := os.ReadDir(runDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("run cache not written: %v", err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(runDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(token)) {
			t.Errorf("token present in run cache entry %s", e.Name())
		}
	}
}

// The base graph's unversioned edges stay in the augmented graph. A call that never told the
// copies apart resolves whatever versions the host lists, as it does without dependency code;
// a versioned node resolves only for a listed version.
func TestDepGraph_UnversionedNodesStillResolve(t *testing.T) {
	edge := func(callee string) plugin.CallEdge {
		return plugin.CallEdge{Caller: plugin.Symbol{SCIP: "scip-typescript npm . . app/`<module-init>`()."}, Callee: plugin.Symbol{SCIP: callee}}
	}
	edges := []plugin.CallEdge{edge("npm:multer#diskStorage"), edge("npm:multer@1.4.2#memoryStorage")}
	for _, tc := range []struct {
		versions []string
		want     []string
	}{
		{nil, []string{"npm:multer#diskStorage"}},
		{[]string{"1.4.2"}, []string{"npm:multer#diskStorage", "npm:multer@1.4.2#memoryStorage"}},
		{[]string{"1.4.3"}, []string{"npm:multer#diskStorage"}},
	} {
		resolved, _, _ := resolveBoundarySymbols("multer", tc.versions, []string{"multer.diskStorage", "multer.memoryStorage"}, edges, buildPackages{})
		var got []string
		for _, s := range resolved {
			got = append(got, s.SCIP)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("versions %v: resolved = %v, want %v", tc.versions, got, tc.want)
		}
	}
}
