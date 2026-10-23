package jsanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// qsSink is the advisory sink every dependency row below looks for.
const qsSink = "npm:qs@6.7.0#parse"

// wrapPkg is a read package "wrap" carrying files, with qs as its dependency.
func wrapPkg(files map[string]string) *depPkg {
	if _, ok := files["package.json"]; !ok {
		files["package.json"] = `{"name":"wrap","version":"1.0.0","dependencies":{"qs":"6.7.0"}}`
	}
	return &depPkg{path: "node_modules/wrap", name: "wrap", version: "1.0.0", files: files}
}

// dotRun reads wrap and qs, loads entry from the app, and returns the call graph and the
// number of paths that reach qs.parse.
func dotRun(t *testing.T, entry string, wrap *depPkg) (plugin.CallGraphResult, int) {
	t.Helper()
	f := newDepFixture(t, map[string]string{"index.js": "const m = require('" + entry + "');\nm();\n"}, wrap, qsPkg("node_modules/qs", "6.7.0"))
	cache := f.diskCache(t)
	cg := withDeps(t, f.dir, f.memStore())
	const purl = "pkg:npm/qs@6.7.0"
	res := mustResolve(t, plugin.ResolveSymbolsRequest{BuildDir: f.dir, PURL: purl, Package: purl, AdvisorySymbols: []string{"qs.parse"}, DependencyCache: cache})
	if got := resolvedSCIPs(res); !slices.Equal(got, []string{qsSink}) {
		// qs is not loaded by any read module, so nothing can reach it.
		return cg, 0
	}
	reach, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: f.dir, Symbols: []string{qsSink}, Package: purl, DependencyCache: cache})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	return cg, len(reach.Paths)
}

// scopedTargetPrefixed reports a scoped limit with a target starting with prefix.
func scopedTargetPrefixed(p plugin.Partiality, prefix string) bool {
	for _, s := range p.Scoped {
		for _, tg := range s.Targets {
			if strings.HasPrefix(tg, prefix) {
				return true
			}
		}
	}
	return false
}

const callsQs = "const qs = require('qs');\nqs.parse('a');\nexports.go = function go() { qs.parse('b'); };\n"

// TestRequireDot_DependencyLoadsResolveAgainstTheDirectory: in dependency code ".", ".." and
// a trailing-slash specifier name a directory beside the caller, as they do in Node's CommonJS
// and ESM resolvers. Each loads the module Node selects there (package.json "main", else index),
// so the path into qs.parse is kept and no limit names a package called "." or "..".
func TestRequireDot_DependencyLoadsResolveAgainstTheDirectory(t *testing.T) {
	cases := []struct {
		name, entry string
		files       map[string]string
	}{
		{"require('..') load only", "wrap/lib/sub", map[string]string{
			"index.js": callsQs, "lib/sub.js": "require('..');\nmodule.exports = function sub() {};\n"}},
		{"require('..') member call", "wrap/lib/sub", map[string]string{
			"index.js": callsQs, "lib/sub.js": "const p = require('..');\nmodule.exports = function sub() { p.go(); };\n"}},
		{"require('.')", "wrap/lib/a", map[string]string{
			"index.js": "", "lib/index.js": callsQs, "lib/a.js": "require('.');\nmodule.exports = function a() {};\n"}},
		{"import '..'", "wrap/lib/sub", map[string]string{
			"index.js": callsQs, "lib/sub.js": "import '..';\nexport default function sub() {}\n"}},
		{"import('..')", "wrap/lib/sub", map[string]string{
			"index.js": callsQs, "lib/sub.js": "import('..');\nmodule.exports = function sub() {};\n"}},
		{"require('..') selects main over index", "wrap/lib/sub", map[string]string{
			"package.json": `{"name":"wrap","version":"1.0.0","main":"lib/main.js","dependencies":{"qs":"6.7.0"}}`,
			"index.js":     "exports.go = function go() {};\n",
			"lib/main.js":  callsQs,
			"lib/sub.js":   "require('..');\nmodule.exports = function sub() {};\n"}},
		{"require('./sub/') is the directory, not sub.js", "wrap/lib/a", map[string]string{
			"index.js":         "",
			"lib/sub.js":       "exports.go = function go() {};\n",
			"lib/sub/index.js": callsQs,
			"lib/a.js":         "require('./sub/');\nmodule.exports = function a() {};\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cg, paths := dotRun(t, tc.entry, wrapPkg(tc.files))
			if paths == 0 {
				t.Errorf("no path to %s; Node loads the module that calls it", qsSink)
			}
			if scopedTargetPrefixed(cg.Partiality, "pkg:npm/.") {
				t.Errorf("a scoped limit names a package that cannot exist: %+v", cg.Partiality.Scoped)
			}
		})
	}
}

// TestRequireDot_DependencyUndecidableDirectoriesWithhold: a directory load whose target the
// lane cannot know declares unresolved_module run-wide. ".." from the package root leaves the
// package; a nested package.json's main is not kept from the tarball; a main that names no
// parsed file gives no index fallback.
func TestRequireDot_DependencyUndecidableDirectoriesWithhold(t *testing.T) {
	cases := []struct {
		name, entry string
		files       map[string]string
	}{
		{"require('..') from the package root", "wrap", map[string]string{
			"package.json": `{"name":"wrap","version":"1.0.0","main":"index.js"}`,
			"index.js":     "require('..');\nmodule.exports = function w() {};\n"}},
		{"nested package.json", "wrap/lib/x/sub", map[string]string{
			"index.js":         "",
			"lib/package.json": `{"main":"index.js"}`,
			"lib/index.js":     callsQs,
			"lib/x/sub.js":     "require('..');\nmodule.exports = function sub() {};\n"}},
		{"unparsed main", "wrap/lib/sub", map[string]string{
			"package.json": `{"name":"wrap","version":"1.0.0","main":"dist/wrap.js","dependencies":{"qs":"6.7.0"}}`,
			"index.js":     callsQs,
			"lib/sub.js":   "require('..');\nmodule.exports = function sub() {};\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cg, _ := dotRun(t, tc.entry, wrapPkg(tc.files))
			if !hasReason(cg.Partiality, plugin.PartialReasonUnresolvedModule) {
				t.Errorf("want run-wide %s; got %v / %+v", plugin.PartialReasonUnresolvedModule, cg.Partiality.Reasons, cg.Partiality.Scoped)
			}
			if scopedTargetPrefixed(cg.Partiality, "pkg:npm/.") {
				t.Errorf("a scoped limit names a package that cannot exist: %+v", cg.Partiality.Scoped)
			}
		})
	}
}

// TestRequireDot_InvalidPackageNameIsUnbounded: "..foo" and "..." are bare in ESM and files in
// CommonJS; no package can carry either name, so a limit bounded to pkg:npm/<name> would bound
// nothing real. The load declares unresolved_module run-wide instead. A valid name the layout
// does not hold keeps its bounded scoped limit.
func TestRequireDot_InvalidPackageNameIsUnbounded(t *testing.T) {
	for _, spec := range []string{"..foo", "...", ".foo", "_foo"} {
		t.Run(spec, func(t *testing.T) {
			cg, _ := dotRun(t, "wrap/lib/sub", wrapPkg(map[string]string{
				"index.js": "", "lib/sub.js": "require('" + spec + "');\nmodule.exports = function sub() {};\n"}))
			if !hasReason(cg.Partiality, plugin.PartialReasonUnresolvedModule) {
				t.Errorf("want run-wide %s; got %v / %+v", plugin.PartialReasonUnresolvedModule, cg.Partiality.Reasons, cg.Partiality.Scoped)
			}
			if scopedTargetPrefixed(cg.Partiality, "pkg:npm/"+spec[:1]) {
				t.Errorf("a scoped limit is bounded to an invalid name: %+v", cg.Partiality.Scoped)
			}
		})
	}
	t.Run("valid name not installed", func(t *testing.T) {
		cg, _ := dotRun(t, "wrap/lib/sub", wrapPkg(map[string]string{
			"index.js": "", "lib/sub.js": "require('absent-pkg');\nmodule.exports = function sub() {};\n"}))
		if !scopedTargetPrefixed(cg.Partiality, "pkg:npm/absent-pkg") {
			t.Errorf("want the bounded scoped limit kept; got %+v", cg.Partiality.Scoped)
		}
	})
}

// TestRequireDot_DependencyPrecision: a specifier only starting with "." ("./.foo" aside) is
// bare, never a file beside the caller; and a package.json exports target of "." is invalid in
// Node, so it selects nothing rather than the package directory.
func TestRequireDot_DependencyPrecision(t *testing.T) {
	t.Run("'.foo' is not a relative load", func(t *testing.T) {
		_, paths := dotRun(t, "wrap/lib/sub", wrapPkg(map[string]string{
			"index.js": "", "lib/.foo.js": callsQs, "lib/sub.js": "require('.foo');\nmodule.exports = function sub() {};\n"}))
		if paths != 0 {
			t.Errorf("'.foo' names a package, not lib/.foo.js; got %d paths", paths)
		}
	})
	t.Run("exports target '.' selects nothing", func(t *testing.T) {
		cg, paths := dotRun(t, "wrap", wrapPkg(map[string]string{
			"package.json": `{"name":"wrap","version":"1.0.0","exports":{".":"."},"dependencies":{"qs":"6.7.0"}}`,
			"index.js":     callsQs}))
		if paths != 0 {
			t.Errorf("an exports target of '.' must select no module; got %d paths", paths)
		}
		if !hasDidNotRun(cg.Partiality) {
			t.Errorf("an entry selecting nothing must withhold; got %v", cg.Partiality.Reasons)
		}
	})
}

// firstPartyGraph builds the first-party call graph of files.
func firstPartyGraph(t *testing.T, files map[string]string) plugin.CallGraphResult {
	t.Helper()
	if _, ok := files["package.json"]; !ok {
		files["package.json"] = `{"name":"app","version":"1.0.0"}`
	}
	cg, _, err := callGraphInternal(writeProgram(t, files))
	if err != nil {
		t.Fatal(err)
	}
	return cg
}

func calleePrefixed(edges []plugin.CallEdge, prefix string) bool {
	return slices.ContainsFunc(edges, func(e plugin.CallEdge) bool { return strings.HasPrefix(e.Callee.SCIP, prefix) })
}

const (
	fpRun   = scipManager + " . . src/a/b/x/run()."
	fpAGo   = scipManager + " . . src/a/index/go()."
	fpEntry = "import { run } from './src/a/b/x';\nrun();\n"
)

// TestRequireDot_FirstPartyLoadsResolveAgainstTheDirectory: first-party "..", "." and
// trailing-slash loads resolve in the tree like their "../" spelling: an edge into the module
// Node selects, no package-boundary node for a package named "..", and no run-wide
// uninspectable_package.
func TestRequireDot_FirstPartyLoadsResolveAgainstTheDirectory(t *testing.T) {
	goIndex := "export function go() { return 1; }\n"
	t.Run("import { go } from '..'", func(t *testing.T) {
		cg := firstPartyGraph(t, map[string]string{"index.js": fpEntry, "src/a/index.js": goIndex,
			"src/a/b/x.js": "import { go } from '..';\nexport function run() { go(); }\n"})
		if !hasEdge(cg.Edges, fpRun, fpAGo) {
			t.Errorf("want %s -> %s; edges %+v", fpRun, fpAGo, cg.Edges)
		}
		if !cg.Partiality.Complete {
			t.Errorf("want a complete graph, as with '../'; got %v", cg.Partiality.Reasons)
		}
	})
	for _, x := range []string{
		"const p = require('..');\nexport function run() { p.go(); }\n",
		"export async function run() { const p = await import('..'); p.go(); }\n",
	} {
		t.Run(x[:24], func(t *testing.T) {
			cg := firstPartyGraph(t, map[string]string{"index.js": fpEntry, "src/a/index.js": goIndex, "src/a/b/x.js": x})
			if calleePrefixed(cg.Edges, boundaryScheme+"..") {
				t.Errorf("an edge enters a package named '..': %+v", cg.Edges)
			}
			if hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage) {
				t.Errorf("an in-tree load declared %s", plugin.PartialReasonUninspectablePackage)
			}
		})
	}
	t.Run("'./x/' is the directory, not x.js", func(t *testing.T) {
		cg := firstPartyGraph(t, map[string]string{
			"index.js":   "import { go } from './x/';\nexport function run() { go(); }\nrun();\n",
			"x.js":       goIndex,
			"x/index.js": goIndex,
		})
		run := scipManager + " . . index/run()."
		if !hasEdge(cg.Edges, run, scipManager+" . . x/index/go().") || hasEdge(cg.Edges, run, scipManager+" . . x/go().") {
			t.Errorf("want only run -> x/index/go(); edges %+v", cg.Edges)
		}
	})
	t.Run("'..' selects the directory's main", func(t *testing.T) {
		cg := firstPartyGraph(t, map[string]string{"index.js": fpEntry, "src/a/index.js": goIndex,
			"src/a/package.json": `{"main":"./main.js"}`, "src/a/main.js": goIndex,
			"src/a/b/x.js": "import { go } from '..';\nexport function run() { go(); }\n"})
		if !hasEdge(cg.Edges, fpRun, scipManager+" . . src/a/main/go().") || hasEdge(cg.Edges, fpRun, fpAGo) {
			t.Errorf("want only run -> src/a/main/go(); edges %+v", cg.Edges)
		}
	})
	t.Run("'./lib' falls through to the directory's main", func(t *testing.T) {
		cg := firstPartyGraph(t, map[string]string{
			"index.js":         "import { go } from './lib';\nexport function run() { go(); }\nrun();\n",
			"lib/package.json": `{"main":"main.js"}`, "lib/main.js": goIndex, "lib/index.js": goIndex,
		})
		run := scipManager + " . . index/run()."
		if !hasEdge(cg.Edges, run, scipManager+" . . lib/main/go().") || hasEdge(cg.Edges, run, scipManager+" . . lib/index/go().") {
			t.Errorf("want only run -> lib/main/go(); edges %+v", cg.Edges)
		}
	})
	t.Run("require.resolve('..') loads nothing", func(t *testing.T) {
		cg := firstPartyGraph(t, map[string]string{"index.js": "const w = require.resolve('..');\nfunction f() { return w; }\nf();\n"})
		if hasDidNotRun(cg.Partiality) {
			t.Errorf("require.resolve declared %v", cg.Partiality.Reasons)
		}
	})
}

// TestRequireDot_FirstPartyUndecidableDirectoriesWithhold: retiring uninspectable_package for a
// dot load is grounded only when the load resolves in the tree. ".." from the build root, an
// unparsed main and an unreadable package.json each leave a did-not-run limit.
func TestRequireDot_FirstPartyUndecidableDirectoriesWithhold(t *testing.T) {
	t.Run("'..' above the build root", func(t *testing.T) {
		cg := firstPartyGraph(t, map[string]string{"index.js": "require('..');\n"})
		if !hasReason(cg.Partiality, plugin.PartialReasonUnresolvedModule) {
			t.Errorf("want %s; got %v", plugin.PartialReasonUnresolvedModule, cg.Partiality.Reasons)
		}
	})
	t.Run("unparsed main has no index fallback", func(t *testing.T) {
		cg := firstPartyGraph(t, map[string]string{
			"index.js":         "import { go } from './lib';\nexport function run() { go(); }\nrun();\n",
			"lib/package.json": `{"main":"dist/lib.js"}`, "lib/index.js": "export function go() { return 1; }\n",
		})
		if !hasReason(cg.Partiality, plugin.PartialReasonUnresolvedModule) {
			t.Errorf("want %s; got %v", plugin.PartialReasonUnresolvedModule, cg.Partiality.Reasons)
		}
		if calleePrefixed(cg.Edges, scipManager+" . . lib/index/") {
			t.Errorf("an unparsed main fell back to index: %+v", cg.Edges)
		}
	})
	t.Run("node_modules is never read from disk", func(t *testing.T) {
		// Without a dependency store the lane reads nothing under node_modules; an unreadable
		// package.json there would mark the run tool_failure if it did.
		dir := writeProgram(t, map[string]string{"package.json": `{"name":"app"}`, "index.js": "require('./node_modules/w/');\n"})
		if err := os.MkdirAll(filepath.Join(dir, "node_modules", "w", "package.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		cg, _, err := callGraphInternal(dir)
		if err != nil {
			t.Fatal(err)
		}
		if hasReason(cg.Partiality, plugin.PartialReasonToolFailure) || !hasDidNotRun(cg.Partiality) {
			t.Errorf("want a withheld load and no read under node_modules; got %v", cg.Partiality.Reasons)
		}
	})
	t.Run("the build root's parent is never read", func(t *testing.T) {
		// A package.json above the root that cannot be read would mark the run tool_failure if
		// the lane opened it.
		parent := t.TempDir()
		if err := os.Mkdir(filepath.Join(parent, "package.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(parent, "app")
		for name, src := range map[string]string{"package.json": `{"name":"app"}`, "index.js": "require('..');\n"} {
			full := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		cg, _, err := callGraphInternal(root)
		if err != nil {
			t.Fatal(err)
		}
		if hasReason(cg.Partiality, plugin.PartialReasonToolFailure) {
			t.Errorf("the lane read a package.json above the build root: %v", cg.Partiality.Reasons)
		}
	})
}

// TestRequireDot_UnderscoreDefaultImport: a default import whose local name starts with "_"
// (Babel's compiled helpers write `import _x from "./x"`) is a binding and a load of "./x",
// not a side-effect import of an empty specifier. Read as the latter it lost the load, and the
// invalid-name gate would turn the empty name into a run-wide limit.
func TestRequireDot_UnderscoreDefaultImport(t *testing.T) {
	t.Run("dependency code", func(t *testing.T) {
		cg, paths := dotRun(t, "wrap", wrapPkg(map[string]string{
			"package.json": `{"name":"wrap","version":"1.0.0","main":"index.mjs","dependencies":{"qs":"6.7.0"}}`,
			"index.mjs":    "import _go from './go.mjs';\nexport default function w() { _go(); }\n",
			"go.mjs":       "import qs from 'qs';\nexport default function go() { qs.parse('a'); }\n"}))
		if paths == 0 {
			t.Errorf("no path to %s through the _go default import", qsSink)
		}
		if hasReason(cg.Partiality, plugin.PartialReasonUnresolvedModule) {
			t.Errorf("a well-formed import declared %s", plugin.PartialReasonUnresolvedModule)
		}
	})
	t.Run("first party", func(t *testing.T) {
		cg := firstPartyGraph(t, map[string]string{
			"index.js": "import _m, { go } from './go';\nexport function run() { go(); }\nrun();\n",
			"go.js":    "export function go() { return 1; }\nexport default 1;\n",
		})
		if !hasEdge(cg.Edges, scipManager+" . . index/run().", scipManager+" . . go/go().") {
			t.Errorf("want run -> go/go(); edges %+v", cg.Edges)
		}
	})
}
