package jsanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// loadListed reports whether cg lists a first-party load declined as an uninspectable package.
func loadListed(cg plugin.CallGraphResult) bool {
	for _, u := range cg.Unresolved {
		if (u.Callee == "require" || u.Callee == "import") && u.Reason == plugin.PartialReasonUninspectablePackage {
			return true
		}
	}
	return false
}

// TestDepGraph_ReadLoad: a first-party load of a package whose code is read, SRI-verified and
// unpatched is not an uninspectable load: the load and the calls it resolves stop withholding
// run-wide. Every way the package's code stays unread, or the load's target stays unknown,
// keeps the run-wide limit and the listed load.
func TestDepGraph_ReadLoad(t *testing.T) {
	const namespaced = "const dep = require('dep');\ndep.run();\n"
	plain := func(files map[string]string) *depPkg {
		m := map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"index.js"}`, "index.js": "exports.run = function run() {};\n"}
		for k, v := range files {
			if v == "" {
				delete(m, k) // an empty file stands for one the package does not ship
				continue
			}
			m[k] = v
		}
		return &depPkg{path: "node_modules/dep", name: "dep", version: "1.0.0", files: m}
	}
	fixture := func(app string, p *depPkg) func(t *testing.T) plugin.CallGraphResult {
		return func(t *testing.T) plugin.CallGraphResult {
			f := newDepFixture(t, map[string]string{"index.js": app}, p)
			return withDeps(t, f.dir, f.memStore())
		}
	}
	const depInit = "scip-typescript npm dep 1.0.0 index/`<module-init>`()."
	const depRun = "scip-typescript npm dep 1.0.0 index/run()."
	const appInit = "scip-typescript npm . . index/`<module-init>`()."
	const craManifest = `{"name":"web","version":"0.1.0","private":true,"dependencies":{"react-scripts":"5.0.1","dep":"1.0.0"},"scripts":{"build":"react-scripts build"}}`

	for _, tc := range []struct {
		name     string
		run      func(t *testing.T) plugin.CallGraphResult
		withheld bool
		check    func(t *testing.T, cg plugin.CallGraphResult)
	}{
		{
			name: "read_namespace_call",
			run:  fixture(namespaced, plain(nil)),
			check: func(t *testing.T, cg plugin.CallGraphResult) {
				if !hasEdge(cg.Edges, appInit, depInit) {
					t.Errorf("the load must link to dep's top level; edges %+v", cg.Edges)
				}
				// A namespace member call resolves to no single function, as for a relative module.
				if len(cg.Unresolved) != 1 || cg.Unresolved[0].Callee != "dep.run" || cg.Unresolved[0].Reason != plugin.PartialReasonDynamicDispatch {
					t.Errorf("only dep.run stays listed, as dynamic dispatch; got %+v", cg.Unresolved)
				}
			},
		},
		{
			name: "read_destructured_call",
			run:  fixture("const { run } = require('dep');\nrun();\n", plain(nil)),
			check: func(t *testing.T, cg plugin.CallGraphResult) {
				if !cg.Partiality.Complete || len(cg.Unresolved) != 0 {
					t.Errorf("a resolved call into a read package hides nothing; got %+v unresolved %+v", cg.Partiality, cg.Unresolved)
				}
				if !hasEdge(cg.Edges, appInit, depRun) {
					t.Errorf("the call must link to dep's run; edges %+v", cg.Edges)
				}
			},
		},
		{
			name: "read_esm_import",
			run:  fixture("import { run } from 'dep';\nrun();\n", plain(nil)),
			check: func(t *testing.T, cg plugin.CallGraphResult) {
				if !cg.Partiality.Complete || !hasEdge(cg.Edges, appInit, depRun) {
					t.Errorf("an import of a read package resolves as a require does; got %+v edges %+v", cg.Partiality, cg.Edges)
				}
			},
		},
		{
			name: "read_exports_json_entry",
			run: fixture("require('dep/data.json');\nrequire('dep');\n", plain(map[string]string{
				"package.json": `{"name":"dep","version":"1.0.0","exports":{".":"./index.js","./data.json":"./data.json"}}`,
				"data.json":    "{}",
			})),
		},
		{
			name: "read_optional_call",
			run:  fixture("const { run } = require('dep');\nrun?.();\n", plain(nil)),
			check: func(t *testing.T, cg plugin.CallGraphResult) {
				// An unconnected call stays listed, as in first-party code, though its target is read.
				if len(cg.Unresolved) != 1 || cg.Unresolved[0].Callee != "run" || cg.Unresolved[0].Reason != plugin.PartialReasonDynamicDispatch {
					t.Errorf("run?.() stays listed as dynamic dispatch; got %+v", cg.Unresolved)
				}
			},
		},
		{
			name:     "builtin_named_package",
			run:      fixture("const ev = require('events');\nev.once();\n", &depPkg{path: "node_modules/events", name: "events", version: "3.3.0", files: map[string]string{"package.json": `{"name":"events","version":"3.3.0","main":"events.js"}`, "events.js": "exports.once = function once() {};\n"}}),
			withheld: true,
		},
		{
			// Node ignores tsconfig paths and loads node_modules/dep, but the first-party graph
			// bound the alias's target, so the load's code is not what the graph read.
			name: "paths_alias_shadowed",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{
					"index.ts":                  namespaced,
					"src/dep.ts":                "export function run() {}\n",
					"tsconfig.json":             `{"compilerOptions":{"baseUrl":".","paths":{"dep":["src/dep"]}}}`,
					"node_modules/dep/index.js": "exports.run = function run() {};\n",
				}, plain(nil))
				return withDeps(t, f.dir, f.memStore())
			},
			withheld: true,
		},
		{
			// A workspace member shadowed by an installed package of the same name: the graph
			// bound the member, Node loads the installed package.
			name: "workspace_member_shadowed",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{
					"package.json":              `{"name":"app","version":"1.0.0","workspaces":["packages/*"]}`,
					"index.js":                  namespaced,
					"packages/dep/package.json": `{"name":"dep","version":"2.0.0"}`,
					"packages/dep/index.js":     "exports.run = function run() {};\n",
					"node_modules/dep/index.js": "exports.run = function run() {};\n",
				}, plain(nil))
				return withDeps(t, f.dir, f.memStore())
			},
			withheld: true,
		},
		{
			// A Create React App build also bundles the module entry, which the lane does not parse.
			name: "cra_front_entry_not_read",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{"package.json": craManifest, "src/index.js": namespaced},
					plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","module":"esm/entry"}`, "esm/entry": "export function run() {}\n"}))
				return withDeps(t, f.dir, f.memStore())
			},
			withheld: true,
		},
		{
			// A subpath load names a file; no resolver reads the module field for it.
			name: "subpath_ignores_module_entry",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{"package.json": craManifest, "src/index.js": "require('dep/lib');\n"},
					plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","module":"esm.js"}`, "esm.js": "export function run() {}\n", "lib.js": "module.exports = 1;\n"}))
				return withDeps(t, f.dir, f.memStore())
			},
		},
		{
			// A webpack build loads the module entry, not main: both are linked from the load.
			name: "module_entry_linked",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{"index.js": "require('dep');\n", "webpack.config.js": "module.exports = { mode: 'production' };\n"},
					plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","module":"esm.js"}`, "esm.js": "export function run() {}\n"}))
				return withDeps(t, f.dir, f.memStore())
			},
			check: func(t *testing.T, cg plugin.CallGraphResult) {
				if !hasEdge(cg.Edges, appInit, depInit) || !hasEdge(cg.Edges, appInit, "scip-typescript npm dep 1.0.0 esm/`<module-init>`().") {
					t.Errorf("the load must link main and module entries; edges %+v", cg.Edges)
				}
			},
		},
		{
			name:     "module_entry_not_parsed",
			run:      fixture("require('dep');\n", plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","module":"esm/entry"}`, "esm/entry": "export function run() {}\n"})),
			withheld: true,
		},
		{
			// A module entry naming no shipped file loads nothing: every resolver falls back.
			name: "module_entry_missing",
			run:  fixture("require('dep');\n", plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","module":"esm/gone.js"}`})),
		},
		{
			// A Vite build swaps node.js for browser.js through the browser map: both are linked.
			name: "browser_map_linked",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{"index.js": "require('dep');\n", "vite.config.js": "export default {};\n"},
					plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"node.js","browser":{"./node.js":"./browser.js"}}`, "index.js": "", "node.js": "exports.run = function run() {};\n", "browser.js": "exports.run = function run() {};\n"}))
				return withDeps(t, f.dir, f.memStore())
			},
			check: func(t *testing.T, cg plugin.CallGraphResult) {
				if !hasEdge(cg.Edges, appInit, "scip-typescript npm dep 1.0.0 node/`<module-init>`().") || !hasEdge(cg.Edges, appInit, "scip-typescript npm dep 1.0.0 browser/`<module-init>`().") {
					t.Errorf("the load must link main and its browser replacement; edges %+v", cg.Edges)
				}
			},
		},
		{
			name:     "browser_map_to_package",
			run:      fixture("require('dep');\n", plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","browser":{"./index.js":"other"}}`})),
			withheld: true,
		},
		{
			name:     "browser_entry_not_parsed",
			run:      fixture("require('dep');\n", plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","browser":"dist/dep.node"}`, "dist/dep.node": "\x7fELF"})),
			withheld: true,
		},
		{
			name: "bundler_alias",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{"index.js": "require('dep');\n", "shim.js": "exports.run = function run() {};\n",
					"webpack.config.js": "module.exports = { resolve: { alias: { dep: './shim.js' } } };\n"}, plain(nil))
				return withDeps(t, f.dir, f.memStore())
			},
			withheld: true,
		},
		{
			// Node loads sub/package.json's main, never sub/index.js (node v26).
			name: "subpath_nested_main",
			run: fixture("require('dep/sub');\n", plain(map[string]string{
				"sub/package.json": `{"main":"./lib/real.js"}`, "sub/index.js": "exports.run = function run() {};\n", "sub/lib/real.js": "exports.run = function run() {};\n"})),
			check: func(t *testing.T, cg plugin.CallGraphResult) {
				if !hasEdge(cg.Edges, appInit, "scip-typescript npm dep 1.0.0 sub/lib/real/`<module-init>`().") || hasEdge(cg.Edges, appInit, "scip-typescript npm dep 1.0.0 sub/index/`<module-init>`().") {
					t.Errorf("the load must link sub/lib/real.js alone; edges %+v", cg.Edges)
				}
			},
		},
		{
			name: "subpath_nested_manifest_unparsed",
			run: fixture("require('dep/sub');\n", plain(map[string]string{
				"sub/package.json": `{"main":`, "sub/index.js": "exports.run = function run() {};\n"})),
			withheld: true,
		},
		{
			// Node loads the extensionless lib/entry, which the lane does not parse (node v26).
			name:     "main_extensionless_beside_js",
			run:      fixture(namespaced, plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"lib/entry"}`, "lib/entry": "exports.run = function run() {};\n", "lib/entry.js": "exports.run = function run() {};\n"})),
			withheld: true,
		},
		{
			// Nothing reaches never(), so its call's edge is filtered out and the call stays listed.
			name: "call_edge_filtered",
			run:  fixture("const { run } = require('dep');\nfunction never() { run(); }\n", plain(nil)),
			check: func(t *testing.T, cg plugin.CallGraphResult) {
				for _, u := range cg.Unresolved {
					if u.Callee == "run" && u.Reason == plugin.PartialReasonDynamicDispatch {
						return
					}
				}
				t.Errorf("a call with no edge in the graph must stay listed; unresolved %+v", cg.Unresolved)
			},
		},
		{
			// A bundler may run esm.js's run, which the call's edge into index.js does not cover.
			name: "call_through_module_entry",
			run: fixture("const { run } = require('dep');\nrun();\n", plain(map[string]string{
				"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","module":"esm.js"}`, "esm.js": "export function run() {}\n"})),
			check: func(t *testing.T, cg plugin.CallGraphResult) {
				for _, u := range cg.Unresolved {
					if u.Callee == "run" && u.Reason == plugin.PartialReasonDynamicDispatch {
						return
					}
				}
				t.Errorf("a call two entries may answer must stay listed; unresolved %+v", cg.Unresolved)
			},
		},
		{
			// The call's load is not covered, so the call keeps its uninspectable decline.
			name: "call_through_unparsed_entry",
			run: fixture("const { run } = require('dep');\nrun();\n", plain(map[string]string{
				"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","module":"esm/entry"}`, "esm/entry": "export function run() {}\n"})),
			withheld: true,
			check: func(t *testing.T, cg plugin.CallGraphResult) {
				for _, u := range cg.Unresolved {
					if u.Callee == "run" && u.Reason == plugin.PartialReasonUninspectablePackage {
						return
					}
				}
				t.Errorf("the call must stay uninspectable; unresolved %+v", cg.Unresolved)
			},
		},
		{
			name:     "exports_target_missing",
			run:      fixture(namespaced, plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","exports":{".":"./gone.json"}}`})),
			withheld: true,
		},
		{
			// Node loads a main outside the package (node v26), which nothing read covers.
			name:     "main_outside_package",
			run:      fixture(namespaced, plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"../shim.js"}`})),
			withheld: true,
		},
		{
			// A yarn berry lock beside the npm lock: the layout is berry and nothing is retracted.
			name: "berry_mixed_lock",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{"index.js": namespaced, "tools/yarn.lock": "__metadata:\n  version: 6\n"}, plain(nil))
				if l := buildDepLayout(context.Background(), f.dir); !l.berry {
					t.Fatalf("fixture: want a berry layout")
				}
				return withDeps(t, f.dir, f.memStore())
			},
			withheld: true,
		},
		{
			name: "cra_front_entry_read",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{"package.json": craManifest, "src/index.js": "require('dep');\n"},
					plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"index.js","module":"esm.js"}`, "esm.js": "export function run() {}\n"}))
				return withDeps(t, f.dir, f.memStore())
			},
		},
		{
			name:     "exports_target_not_relative",
			run:      fixture(namespaced, plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","exports":{".":"index.js"}}`})),
			withheld: true,
		},
		{
			name:     "no_main_no_index",
			run:      fixture(namespaced, plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0"}`, "index.js": "", "lib.js": "exports.run = function run() {};\n"})),
			withheld: true,
		},
		{
			name: "sri_mismatch",
			run: func(t *testing.T) plugin.CallGraphResult {
				p := plain(nil)
				f := newDepFixture(t, map[string]string{"index.js": namespaced}, p)
				tampered := artifactcache.NewMemStore(map[artifactcache.Ref][]byte{f.ref(p): buildTgz(t, map[string]string{"package.json": `{"name":"dep"}`, "index.js": "exports.run = function run() {};\n"})})
				return withDeps(t, f.dir, tampered)
			},
			withheld: true,
		},
		{
			name: "cache_miss",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{"index.js": namespaced}, plain(nil))
				return withDeps(t, f.dir, artifactcache.NewDeclaredAbsentStore())
			},
			withheld: true,
		},
		{
			name: "budget_overrun",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{"index.js": namespaced}, plain(nil))
				res, _, err := callGraphWithDeps(context.Background(), f.dir, f.memStore(), 0)
				if err != nil {
					t.Fatal(err)
				}
				return res
			},
			withheld: true,
		},
		{
			// Node falls back to index.js when main names no file (node v26).
			name: "main_missing_falls_back_to_index",
			run:  fixture(namespaced, plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"lib/gone.js"}`})),
			check: func(t *testing.T, cg plugin.CallGraphResult) {
				if !hasEdge(cg.Edges, appInit, depInit) {
					t.Errorf("the load must link index.js; edges %+v", cg.Edges)
				}
			},
		},
		{
			name:     "main_missing_no_index",
			run:      fixture(namespaced, plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","main":"lib/gone.js"}`, "index.js": "", "lib.js": "exports.run = function run() {};\n"})),
			withheld: true,
		},
		{
			name:     "exports_target_not_read",
			run:      fixture(namespaced, plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","exports":{".":["./index.js","./lib/gone.js"]}}`})),
			withheld: true,
		},
		{
			name:     "exports_selects_nothing",
			run:      fixture("require('dep/hidden');\n", plain(map[string]string{"package.json": `{"name":"dep","version":"1.0.0","exports":{".":"./index.js"}}`, "hidden.js": "module.exports = 1;\n"})),
			withheld: true,
		},
		{
			name:     "subpath_not_read",
			run:      fixture("require('dep/lib/gone');\n", plain(nil)),
			withheld: true,
		},
		{
			name: "self_reference",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{"index.js": namespaced, "package.json": `{"name":"dep","version":"1.0.0","exports":"./index.js"}`}, plain(nil))
				return withDeps(t, f.dir, f.memStore())
			},
			withheld: true,
		},
		{
			name: "incomplete_layout",
			run: func(t *testing.T) plugin.CallGraphResult {
				f := newDepFixture(t, map[string]string{
					"index.js":                namespaced,
					"tools/package.json":      `{"name":"tools","version":"1.0.0","dependencies":{"x":"1.0.0"}}`,
					"tools/package-lock.json": "{",
				}, plain(nil))
				if l := buildDepLayout(context.Background(), f.dir); !l.incomplete || l.byPath["node_modules/dep"] == nil {
					t.Fatalf("fixture: want an incomplete layout that still places dep; incomplete=%v", l.incomplete)
				}
				return withDeps(t, f.dir, f.memStore())
			},
			withheld: true,
		},
		{
			name: "pnpm_patched",
			run: func(t *testing.T) plugin.CallGraphResult {
				q := qPkg("1.0.0")
				lock := pnpmLockText(t, "9.0", map[string]map[string]string{".": {"q": "1.0.0"}}, q)
				lock = strings.Replace(lock, "importers:", "patchedDependencies:\n  'q@1.0.0':\n    hash: abc\n    path: patches/q.patch\n\nimporters:", 1)
				lock = strings.Replace(lock, "version: '1.0.0'", "version: '1.0.0(patch_hash=abc)'", 1)
				lock = strings.Replace(lock, "\n  'q@1.0.0': {}", "\n  'q@1.0.0(patch_hash=abc)': {}", 1)
				dir := semProgram(t, pnpmLockFile, lock, map[string]string{
					"index.js":            "const q = require('q');\nq.go();\n",
					"package.json":        manifestWith("app", map[string]string{"q": "1.0.0"}, ""),
					"pnpm-workspace.yaml": "patchedDependencies:\n  'q@1.0.0': patches/q.patch\n",
					"patches/q.patch":     patchHead,
				})
				cg := withDeps(t, dir, semStore(t, q))
				if !hasScoped(cg.Partiality, plugin.PartialReasonUninspectablePackage, makePURL("q", "1.0.0")) {
					t.Fatalf("fixture: q must be patched and unread; got %+v", cg.Partiality)
				}
				return cg
			},
			withheld: true,
		},
		{
			name: "pnpm_read_control",
			run: func(t *testing.T) plugin.CallGraphResult {
				q := qPkg("1.0.0")
				lock := pnpmLockText(t, "9.0", map[string]map[string]string{".": {"q": "1.0.0"}}, q)
				dir := semProgram(t, pnpmLockFile, lock, map[string]string{
					"index.js":     "const q = require('q');\nq.go();\n",
					"package.json": manifestWith("app", map[string]string{"q": "1.0.0"}, ""),
				})
				return withDeps(t, dir, semStore(t, q))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg := tc.run(t)
			if got := runWide(cg) || loadListed(cg); got != tc.withheld {
				t.Errorf("withheld = %v, want %v; partiality %+v unresolved %+v", got, tc.withheld, cg.Partiality, cg.Unresolved)
			}
			if tc.withheld && !(runWide(cg) && loadListed(cg)) {
				t.Errorf("an unread load keeps both the run-wide limit and its listed site; partiality %+v unresolved %+v", cg.Partiality, cg.Unresolved)
			}
			if tc.check != nil {
				tc.check(t, cg)
			}
		})
	}
}

// TestDepGraph_ReadLoadBoundaryCall: a call on a value a read package returned enters the
// package at a boundary its read code does not resolve, so it keeps the run-wide limit while
// the load itself is covered.
func TestDepGraph_ReadLoadBoundaryCall(t *testing.T) {
	p := &depPkg{path: "node_modules/dep", name: "dep", version: "1.0.0", files: map[string]string{
		"package.json": `{"name":"dep","version":"1.0.0","main":"index.js"}`,
		"index.js":     "module.exports = function make() { return { listen() {} }; };\n",
	}}
	f := newDepFixture(t, map[string]string{"index.js": "const make = require('dep');\nconst app = make();\napp.listen();\n"}, p)
	cg := withDeps(t, f.dir, f.memStore())
	if !runWide(cg) || loadListed(cg) {
		t.Errorf("want run-wide kept and the load not listed; partiality %+v unresolved %+v", cg.Partiality, cg.Unresolved)
	}
}

// TestDepGraph_ReadLoadDepsOffUnchanged: without dependency code the first-party graph of a
// program that loads packages is the graph callGraphInternal builds, decline for decline.
func TestDepGraph_ReadLoadDepsOffUnchanged(t *testing.T) {
	for _, app := range []string{
		"const dep = require('dep');\ndep.run();\n",
		"const { run } = require('dep');\nrun();\n",
		"import { run } from 'dep';\nrun();\nrequire('fs').readFileSync('x');\n",
	} {
		dir := writeProgram(t, map[string]string{"index.js": app, "package.json": `{"name":"app","version":"1.0.0"}`})
		cg, err := callGraphFor(context.Background(), dir, "")
		if err != nil {
			t.Fatal(err)
		}
		if !runWide(cg) || !loadListed(cg) {
			t.Errorf("%q: dependency code off keeps every package load uninspectable; got %+v unresolved %+v", app, cg.Partiality, cg.Unresolved)
		}
	}
}
