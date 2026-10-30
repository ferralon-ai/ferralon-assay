package jsanalysis

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// tgzEntry is one tarball entry; size > len(body) pads the body with zero bytes.
type tgzEntry struct {
	name string
	body string
	size int64
}

// buildRawTgz packs entries exactly as given: no "package/" prefix, duplicates kept.
func buildRawTgz(t *testing.T, entries ...tgzEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		size := max(e.size, int64(len(e.body)))
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: size, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, e.body); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(tw, zeros{}, size-int64(len(e.body))); err != nil {
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

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

const (
	guardIdle    = "module.exports = 1;\n"
	guardPURL    = "pkg:npm/dep@1.0.0"
	guardDepMain = `{"name":"dep","version":"1.0.0","main":"index.js"}`
)

func guardPkg(files map[string]string) *depPkg {
	m := map[string]string{"package.json": guardDepMain, "index.js": "exports.run = function run() {};\n"}
	for k, v := range files {
		m[k] = v
	}
	return &depPkg{path: "node_modules/dep", name: "dep", version: "1.0.0", files: m}
}

func readsDep(cg plugin.CallGraphResult) bool {
	return slices.ContainsFunc(cg.Edges, func(e plugin.CallEdge) bool {
		return strings.Contains(e.Caller.SCIP, " dep 1.0.0 ") || strings.Contains(e.Callee.SCIP, " dep 1.0.0 ")
	})
}

// TestDepGuards_HostileShapesRefusedFast (F1): each source shape that runs the parser's forward
// scans to the end of the file from every position is refused before it is parsed, fast, and
// surfaces as unsupported_phase1.
func TestDepGuards_HostileShapesRefusedFast(t *testing.T) {
	for _, shape := range []string{"a(", "[", "x=>", "`${", "function f(){", "class A{m(){"} {
		t.Run(shape, func(t *testing.T) {
			src := strings.Repeat(shape, (1<<20)/len(shape))
			f := newDepFixture(t, map[string]string{"index.js": guardIdle}, guardPkg(map[string]string{"index.js": src}))
			start := time.Now()
			cg := withDeps(t, f.dir, f.memStore())
			if d := time.Since(start); d > 15*time.Second {
				t.Errorf("a 1 MB %q file took %v; it must be refused before it is parsed", shape, d)
			}
			if !hasReason(cg.Partiality, plugin.PartialReasonUnsupported) {
				t.Errorf("a refused file must surface as %s; got %+v", plugin.PartialReasonUnsupported, cg.Partiality)
			}
		})
	}
}

// TestDepGuards_RealSourceWithinWork: ordinary package code stays well inside the estimate.
func TestDepGuards_RealSourceWithinWork(t *testing.T) {
	src := strings.Repeat("function f(a, b) { return [a, b].map((x) => x + `${a}`); }\nconst g = (y) => ({ y, z: f(y, 1) });\n", 8000)
	if !depWorkWithin(src) {
		t.Error("ordinary code must not be refused")
	}
}

// blockingParser stands in for parseFile: it returns only when released or after limit.
func blockingParser(t *testing.T, limit time.Duration) {
	t.Helper()
	release := make(chan struct{})
	prev := depParser
	depParser = func(module string, f depFile) parseResult {
		select {
		case <-release:
		case <-time.After(limit):
		}
		return parseResult{module: module}
	}
	t.Cleanup(func() {
		close(release)
		depParser = prev
	})
}

// TestDepGuards_FileParseTimeout (F1): a parse the estimate lets through but that never finishes
// is abandoned at depFileParseTimeout and surfaces as unsupported_phase1.
func TestDepGuards_FileParseTimeout(t *testing.T) {
	blockingParser(t, 20*time.Second)
	prev := depFileParseTimeout
	depFileParseTimeout = 50 * time.Millisecond
	t.Cleanup(func() { depFileParseTimeout = prev })

	f := newDepFixture(t, map[string]string{"index.js": guardIdle}, guardPkg(nil))
	start := time.Now()
	cg := withDeps(t, f.dir, f.memStore())
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("a stuck parse held the run for %v", d)
	}
	if !hasReason(cg.Partiality, plugin.PartialReasonUnsupported) {
		t.Errorf("an abandoned parse must surface as %s; got %+v", plugin.PartialReasonUnsupported, cg.Partiality)
	}
}

// TestDepGuards_BudgetIsReal (F1): when the read budget ends while a parse is still running, the
// run returns at the budget with tool_failure instead of waiting for the parse.
func TestDepGuards_BudgetIsReal(t *testing.T) {
	blockingParser(t, 20*time.Second)
	prev := depFileParseTimeout
	depFileParseTimeout = time.Hour
	t.Cleanup(func() { depFileParseTimeout = prev })

	f := newDepFixture(t, map[string]string{"index.js": guardIdle}, guardPkg(nil))
	start := time.Now()
	res, _, err := callGraphWithDeps(context.Background(), f.dir, f.memStore(), 300*time.Millisecond)
	if err != nil {
		t.Fatalf("a spent budget is a limit, not an error: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the run waited %v for a parse past its budget", d)
	}
	if !hasScoped(res.Partiality, plugin.PartialReasonToolFailure, guardPURL) || !hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
		t.Errorf("a budget overrun must carry tool_failure, scoped and run-wide; got %+v", res.Partiality)
	}
}

// TestDepGuards_RunSourceCap (F3): a package past the run's parsed-source cap stays unparsed
// with a scoped tool_failure.
func TestDepGuards_RunSourceCap(t *testing.T) {
	f := newDepFixture(t, map[string]string{"index.js": "require('dep').run();\n"}, guardPkg(nil))
	if cg := withDeps(t, f.dir, f.memStore()); !readsDep(cg) {
		t.Fatalf("control: under the cap dep is read; edges %+v", cg.Edges)
	}
	prev := depRunSourceCap
	depRunSourceCap = 1
	t.Cleanup(func() { depRunSourceCap = prev })
	cg := withDeps(t, f.dir, f.memStore())
	if readsDep(cg) {
		t.Errorf("a package past the cap must not be parsed; edges %+v", cg.Edges)
	}
	if !hasScoped(cg.Partiality, plugin.PartialReasonToolFailure, guardPURL) {
		t.Errorf("a package past the cap must carry a scoped tool_failure; got %+v", cg.Partiality)
	}

	// A capped package under a lock that does not record install scripts withholds run-wide.
	v1 := newDepFixture(t, map[string]string{"index.js": guardIdle}, guardPkg(nil))
	p := v1.pkgs[0]
	lock := `{"name":"app","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{"dep":{"version":"1.0.0","resolved":"https://registry.npmjs.org/dep/-/dep-1.0.0.tgz","integrity":"` + sri(p.tgz) + `"}}}`
	if err := os.WriteFile(filepath.Join(v1.dir, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	depRunSourceCap = prev
	if cg := withDeps(t, v1.dir, v1.memStore()); hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage) {
		t.Fatalf("control: a read v1 package does not withhold run-wide; got %+v", cg.Partiality)
	}
	depRunSourceCap = 1
	cg = withDeps(t, v1.dir, v1.memStore())
	if !hasScoped(cg.Partiality, plugin.PartialReasonToolFailure, guardPURL) || !hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage) {
		t.Errorf("a capped v1 package must carry a scoped tool_failure and run-wide uninspectable; got %+v", cg.Partiality)
	}
}

// TestDepGuards_TarballShape: a tarball holding an entry twice (N7), also as two names differing
// only in case (one file on a case-insensitive filesystem), or a top-level entry outside
// package/ past the unpacked-size cap (F2), leaves the package unread with a scoped limit.
func TestDepGuards_TarballShape(t *testing.T) {
	const run = "exports.run = function run() {};\n"
	for _, tc := range []struct {
		name    string
		entries []tgzEntry
	}{
		{"duplicate_entry", []tgzEntry{
			{name: "package/package.json", body: guardDepMain},
			{name: "package/index.js", body: run},
			{name: "package/index.js", body: "exports.run = function run() { other(); };\n"},
		}},
		{"case_colliding_manifest", []tgzEntry{
			{name: "package/package.json", body: guardDepMain},
			{name: "package/PACKAGE.JSON", body: guardDepMain},
			{name: "package/index.js", body: run},
		}},
		{"case_colliding_source", []tgzEntry{
			{name: "package/package.json", body: guardDepMain},
			{name: "package/index.js", body: run},
			{name: "package/Index.js", body: "exports.run = function run() { other(); };\n"},
		}},
		{"top_level_entry_past_unpacked_cap", []tgzEntry{
			{name: "package/package.json", body: guardDepMain},
			{name: "package/index.js", body: run},
			{name: "pad", size: maxUnpackedBytes + tarSlack},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := guardPkg(nil)
			p.tgz = buildRawTgz(t, tc.entries...)
			f := newDepFixture(t, map[string]string{"index.js": "require('dep').run();\n"}, p)
			cg := withDeps(t, f.dir, f.memStore())
			if readsDep(cg) {
				t.Errorf("the package must stay unread; edges %+v", cg.Edges)
			}
			if !hasScoped(cg.Partiality, plugin.PartialReasonUninspectablePackage, guardPURL) {
				t.Errorf("an unread package carries a scoped limit; got %+v", cg.Partiality)
			}
		})
	}
	t.Run("control", func(t *testing.T) {
		p := guardPkg(nil)
		p.tgz = buildRawTgz(t, tgzEntry{name: "package/package.json", body: guardDepMain}, tgzEntry{name: "package/index.js", body: run})
		f := newDepFixture(t, map[string]string{"index.js": "require('dep').run();\n"}, p)
		if cg := withDeps(t, f.dir, f.memStore()); !readsDep(cg) {
			t.Errorf("a well-formed tarball is read; edges %+v", cg.Edges)
		}
	})
}

// TestDepGuards_UnknownInstallScripts (B1, B2): a lock that does not record install scripts (npm
// v1, pnpm, yarn classic) leaves each package it pins that is not read with a scoped limit and
// withholds run-wide, since the package may run one at install.
func TestDepGuards_UnknownInstallScripts(t *testing.T) {
	integrity := sri([]byte("dep"))
	manifest := `{"name":"app","version":"1.0.0","dependencies":{"dep":"1.0.0"}}`
	for _, tc := range []struct {
		name, lockName, lock string
		runWide              bool
	}{
		{"npm_v3_control", "package-lock.json", `{"name":"app","lockfileVersion":3,"requires":true,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"dep":"1.0.0"}},"node_modules/dep":{"version":"1.0.0","resolved":"https://registry.npmjs.org/dep/-/dep-1.0.0.tgz","integrity":"` + integrity + `"}}}`, false},
		{"npm_v1", "package-lock.json", `{"name":"app","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{"dep":{"version":"1.0.0","resolved":"https://registry.npmjs.org/dep/-/dep-1.0.0.tgz","integrity":"` + integrity + `"}}}`, true},
		{"pnpm", "pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      dep:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n  dep@1.0.0:\n    resolution: {integrity: " + integrity + "}\n\nsnapshots:\n\n  dep@1.0.0: {}\n", true},
		{"yarn_classic", "yarn.lock", "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\ndep@1.0.0:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/dep/-/dep-1.0.0.tgz\"\n  integrity " + integrity + "\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeProgram(t, map[string]string{"package.json": manifest, tc.lockName: tc.lock, "index.js": guardIdle})
			cg := withDeps(t, dir, artifactcache.NewDeclaredAbsentStore())
			if !hasScoped(cg.Partiality, plugin.PartialReasonUninspectablePackage, guardPURL) {
				t.Errorf("an unread pinned package carries a scoped limit; got %+v", cg.Partiality)
			}
			if got := hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage); got != tc.runWide {
				t.Errorf("run-wide uninspectable = %v, want %v; got %+v", got, tc.runWide, cg.Partiality)
			}
		})
	}
}

// TestDepGuards_DualPackageOtherHalf (N2): the .mjs half of a dual package is parsed too, so an
// eval in it surfaces as evaluated_code.
func TestDepGuards_DualPackageOtherHalf(t *testing.T) {
	dual := func(mjs string) *depPkg {
		return guardPkg(map[string]string{
			"package.json": `{"name":"dep","version":"1.0.0","exports":{"import":"./index.mjs","require":"./index.js"}}`,
			"index.mjs":    mjs,
		})
	}
	clean := newDepFixture(t, map[string]string{"index.js": guardIdle}, dual("export function run() {}\n"))
	if cg := withDeps(t, clean.dir, clean.memStore()); hasReason(cg.Partiality, plugin.PartialReasonEvaluatedCode) {
		t.Fatalf("control: no eval, no evaluated_code; got %+v", cg.Partiality)
	}
	f := newDepFixture(t, map[string]string{"index.js": guardIdle}, dual("export function run(s) { return eval(s); }\n"))
	if cg := withDeps(t, f.dir, f.memStore()); !hasReason(cg.Partiality, plugin.PartialReasonEvaluatedCode) {
		t.Errorf("an eval in the .mjs half must surface as evaluated_code; got %+v", cg.Partiality)
	}
	imp := newDepFixture(t, map[string]string{"index.js": "import { run } from 'dep';\nrun();\n"}, dual("export function run() {}\n"))
	if cg := withDeps(t, imp.dir, imp.memStore()); !loadsDepModule(cg, "index.mjs") {
		t.Errorf("an import must load the .mjs half its exports target names; edges %+v", cg.Edges)
	}
}

// loadsDepModule reports whether the graph links a first-party module's top level to dep's module
// under inner (its path in the package, extension stripped unless parsed as a sibling).
func loadsDepModule(cg plugin.CallGraphResult, inner string) bool {
	want := scipManager + " dep 1.0.0 " + inner + "/"
	return slices.ContainsFunc(cg.Edges, func(e plugin.CallEdge) bool { return strings.HasPrefix(e.Callee.SCIP, want) })
}

// TestDepGuards_ExportsConditions (N8, M3d): an exports map gives a require only its require
// target; any other load may be transpiled to require, so it takes both.
func TestDepGuards_ExportsConditions(t *testing.T) {
	p := guardPkg(map[string]string{
		"package.json": `{"name":"dep","version":"1.0.0","exports":{"import":"./esm/index.js","require":"./cjs/index.js"}}`,
		"esm/index.js": "export function run() {}\n",
		"cjs/index.js": "exports.run = function run() {};\n",
	})
	for _, tc := range []struct {
		name, src string
		esm       bool
	}{
		{"import", "import { run } from 'dep';\nrun();\n", true},
		{"require", "const { run } = require('dep');\nrun();\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDepFixture(t, map[string]string{"index.js": tc.src}, p)
			cg := withDeps(t, f.dir, f.memStore())
			if !loadsDepModule(cg, "cjs/index") || loadsDepModule(cg, "esm/index") != tc.esm {
				t.Errorf("%s: want cjs/index, esm/index=%v; edges %+v", tc.name, tc.esm, cg.Edges)
			}
		})
	}
}

// TestDepGuards_BindingGypImpliesInstall (N8, M4c): a binding.gyp with no install or preinstall
// script makes npm run `node-gyp rebuild`, an install script, so it withholds run-wide.
func TestDepGuards_BindingGypImpliesInstall(t *testing.T) {
	f := newDepFixture(t, map[string]string{"index.js": guardIdle}, guardPkg(map[string]string{"binding.gyp": "{}\n"}))
	if cg := withDeps(t, f.dir, f.memStore()); !hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage) {
		t.Errorf("binding.gyp without an install script must withhold run-wide; got %+v", cg.Partiality)
	}
	scripted := newDepFixture(t, map[string]string{"index.js": guardIdle}, guardPkg(map[string]string{
		"binding.gyp":  "{}\n",
		"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","scripts":{"install":"prebuild-install"}}`,
	}))
	if cg := withDeps(t, scripted.dir, scripted.memStore()); !hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage) {
		t.Errorf("an explicit install script withholds run-wide too; got %+v", cg.Partiality)
	}
}

// TestDepGuards_ReadPackageNoEntry (N6): a dependency load of a read package whose entry selects
// no parsed module leaves what the load runs unread: unresolved_module.
func TestDepGuards_ReadPackageNoEntry(t *testing.T) {
	loader := guardPkg(map[string]string{"index.js": "const b = require('b');\nexports.run = function run() { b(); };\n"})
	b := func(main string) *depPkg {
		return &depPkg{path: "node_modules/b", name: "b", version: "1.0.0", files: map[string]string{
			"package.json": `{"name":"b","version":"1.0.0","main":"` + main + `"}`,
			"lib/b.js":     "module.exports = function b() {};\n",
		}}
	}
	ok := newDepFixture(t, map[string]string{"index.js": guardIdle}, loader, b("lib/b.js"))
	if cg := withDeps(t, ok.dir, ok.memStore()); hasReason(cg.Partiality, plugin.PartialReasonUnresolvedModule) {
		t.Fatalf("control: an entry that selects a module adds no unresolved_module; got %+v", cg.Partiality)
	}
	f := newDepFixture(t, map[string]string{"index.js": guardIdle}, loader, b("build/b.node"))
	if cg := withDeps(t, f.dir, f.memStore()); !hasReason(cg.Partiality, plugin.PartialReasonUnresolvedModule) {
		t.Errorf("an entry that selects no parsed module must surface as unresolved_module; got %+v", cg.Partiality)
	}
}

// TestDepGuards_FrontendEntries (N3): a stock Create React App's src loads a package's module
// entry beside its main, and so may any program a bundler builds: both are linked either way.
func TestDepGuards_FrontendEntries(t *testing.T) {
	p := guardPkg(map[string]string{
		"package.json": `{"name":"dep","version":"1.0.0","main":"cjs.js","module":"esm.js"}`,
		"cjs.js":       "exports.run = function run() {};\n",
		"esm.js":       "export function run() {}\n",
	})
	const src = "import { run } from 'dep';\nrun();\n"
	cra := newDepFixture(t, map[string]string{
		"package.json": `{"name":"web","version":"0.1.0","private":true,"dependencies":{"react-scripts":"5.0.1","dep":"1.0.0"},"scripts":{"start":"react-scripts start","build":"react-scripts build"}}`,
		"src/index.js": src,
	}, p)
	if cg := withDeps(t, cra.dir, cra.memStore()); !loadsDepModule(cg, "esm") || !loadsDepModule(cg, "cjs") {
		t.Errorf("a CRA module must load both the module and main entries; edges %+v", cg.Edges)
	}
	node := newDepFixture(t, map[string]string{"src/index.js": src}, p)
	if cg := withDeps(t, node.dir, node.memStore()); !loadsDepModule(cg, "esm") || !loadsDepModule(cg, "cjs") {
		t.Errorf("a module a bundler may build must load both the module and main entries; edges %+v", cg.Edges)
	}
}

// TestDepGuards_UndecodedLockWithholds: a pnpm or yarn classic lock the line-based readers decode
// to no entries, while the manifest declares a dependency, leaves the run withheld. A project that
// declares nothing stays complete.
func TestDepGuards_UndecodedLockWithholds(t *testing.T) {
	declares := `{"name":"app","version":"1.0.0","dependencies":{"dep":"1.0.0"}}`
	bare := `{"name":"app","version":"1.0.0"}`
	for _, tc := range []struct {
		name, manifest, lockName, lock string
		withheld                       bool
	}{
		{"garbage_pnpm", declares, "pnpm-lock.yaml", "lockfileVersion: [[[ \x00\x01 not yaml\n", true},
		{"garbage_yarn", declares, "yarn.lock", "\x00\x01 this is not a yarn lockfile {{{\n", true},
		{"garbage_yarn_build_member", `{"name":"app","version":"1.0.0","private":true,"workspaces":["build/*"]}`, "yarn.lock", "\x00\x01 this is not a yarn lockfile {{{\n", true},
		{"garbage_pnpm_vendor_member", bare, "pnpm-lock.yaml", "lockfileVersion: [[[ \x00\x01 not yaml\n", true},
		{"garbage_yarn_symlinked_member", `{"name":"app","version":"1.0.0","private":true,"workspaces":["packages/*"]}`, "yarn.lock", "\x00\x01 this is not a yarn lockfile {{{\n", true},
		{"empty_pnpm_no_deps", bare, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n", false},
		{"empty_yarn_no_deps", bare, "yarn.lock", "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"package.json": tc.manifest, tc.lockName: tc.lock, "index.js": guardIdle}
			switch tc.name {
			case "garbage_yarn_build_member":
				files["build/app/package.json"] = declares
			case "garbage_pnpm_vendor_member":
				files["pnpm-workspace.yaml"] = "packages:\n  - 'vendor/*'\n"
				files["vendor/lib/package.json"] = declares
			}
			dir := writeProgram(t, files)
			if tc.name == "garbage_yarn_symlinked_member" {
				outside := writeProgram(t, map[string]string{"package.json": declares})
				if err := os.MkdirAll(filepath.Join(dir, "packages"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(dir, "packages", "app")); err != nil {
					t.Fatal(err)
				}
			}
			cg := withDeps(t, dir, artifactcache.NewDeclaredAbsentStore())
			if cg.Partiality.Complete == tc.withheld {
				t.Errorf("complete = %v, want %v; got %+v", cg.Partiality.Complete, !tc.withheld, cg.Partiality)
			}
		})
	}
}

// TestDepGuards_UnidentifiedPinIncomplete: a pinned entry the lock names without a coordinate or
// version leaves the layout incomplete.
func TestDepGuards_UnidentifiedPinIncomplete(t *testing.T) {
	for _, d := range []plugin.ResolvedDependency{{Coordinate: "dep"}, {Version: "1.0.0"}} {
		l := &depLayout{byPath: map[string]*depEntry{}}
		l.addUnplacedDeps([]plugin.ResolvedDependency{{Coordinate: "ok", Version: "1.0.0"}, d})
		if !l.incomplete {
			t.Errorf("%+v: layout must be incomplete", d)
		}
	}
	l := &depLayout{byPath: map[string]*depEntry{}}
	l.addUnplacedDeps([]plugin.ResolvedDependency{{Coordinate: "ok", Version: "1.0.0"}})
	if l.incomplete || len(l.unplaced) != 1 {
		t.Errorf("control: an identified pin is recorded and complete; incomplete=%v unplaced=%d", l.incomplete, len(l.unplaced))
	}
}
