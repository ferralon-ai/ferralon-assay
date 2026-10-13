package trigger

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jsanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestUndeterminedReason_JSUnreadCodeNeverRefutes runs JS programs that load code the lane
// does not read through the real producer (jsanalysis CallGraph and Reachability), records
// the result the way the reachability stage does when no vulnerable symbol was resolved, and
// asserts the refutation gate holds the verdict undetermined. Each program has call edges,
// so the gate's zero-edge arm cannot be what holds it.
func TestUndeterminedReason_JSUnreadCodeNeverRefutes(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		files map[string]string // added to or replacing the default tree
	}{
		{"binding alias", `
const lib = require('json5'); const p = lib;
function load(s) { return p.parse(s); }
load(process.argv[2]);
`, nil},
		{"inline require", `
function load(s) { return require('json5').parse(s); }
load(process.argv[2]);
`, nil},
		{"aliased require", `
const r = require;
function load(s) { return r('json5').parse(s); }
load(process.argv[2]);
`, nil},
		{"concatenated require", `
function load(s, n) { return require('./plugins/' + n).parse(s); }
load(process.argv[2], 'json5');
`, nil},
		{"interpolated template require", `
function load(s, n) { return require(` + "`./${n}`" + `).parse(s); }
load(process.argv[2], 'json5');
`, nil},
		{"native addon", `
const addon = require('./build/Release/x.node');
function load(s) { return addon.parse(s); }
load(process.argv[2]);
`, nil},
		{"generated module absent from the tree", `
const gen = require('./dist/gen');
function load(s) { return gen.parse(s); }
load(process.argv[2]);
`, nil},
		{"require inside a typeof test", `
function load(s) { if (typeof require('json5').parse === 'function') return s; return s; }
load(process.argv[2]);
`, nil},
		{"imports entry whose require branch is a package", `
const j = require('#j');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json": `{"name":"fixture","imports":{"#j":{"import":"./esm.js","require":"json5"}},"dependencies":{"json5":"2.2.1"}}`,
			"esm.js":       "export function parse(s) { return s; }\n",
		}},
		{"workspace member whose require branch is not in the tree", `
const m = require('m');
function load(s) { return m.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json":            `{"name":"fixture","workspaces":["packages/*"]}`,
			"packages/m/package.json": `{"name":"m","exports":{".":{"import":"./src/index.js","require":"./lib/index.cjs"}}}`,
			"packages/m/src/index.js": "export function parse(s) { return s; }\n",
		}},
		{"literal import() of an imports entry with a development branch to a package", `
async function load(s) { const m = await import('#cfg'); return m.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json": `{"name":"fixture","dependencies":{"json5":"2.2.1"},"imports":{"#cfg":{"development":"json5","default":"./plugins/index.js"}}}`,
		}},
		{"literal import() of a workspace member with a development export", `
async function load(s) { const m = await import('m'); return m.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json":            `{"name":"fixture","workspaces":["packages/*"],"dependencies":{"json5":"2.2.1"}}`,
			"packages/m/package.json": `{"name":"m","exports":{".":{"development":"./dev.js","default":"./src/index.js"}}}`,
			"packages/m/src/index.js": "function parse(s) { return s; }\nmodule.exports = { parse };\n",
		}},
		{"literal import() of an installed package whose development export reaches the symbol", `
async function load(s) { const m = await import('cfg'); return m.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json":                  `{"name":"fixture","dependencies":{"cfg":"1.0.0","json5":"2.2.1"}}`,
			"node_modules/cfg/package.json": `{"name":"cfg","exports":{".":{"development":"./dev.js","default":"./prod.js"}}}`,
			"node_modules/cfg/dev.js":       "const j = require('json5');\nexports.parse = (s) => j.parse(s);\n",
			"node_modules/cfg/prod.js":      "exports.parse = (s) => s;\n",
		}},
		{"literal import() of a self-reference with a development export", `
async function load(s) { const m = await import('fixture'); return m.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json": `{"name":"fixture","dependencies":{"json5":"2.2.1"},"exports":{".":{"development":"./dev.js","default":"./plugins/index.js"}}}`,
		}},
		{"literal import() of a workspace member a tsconfig paths alias shadows", `
async function load(s) { const m = await import('m'); return m.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json":            `{"name":"fixture","workspaces":["packages/*"],"dependencies":{"json5":"2.2.1"}}`,
			"tsconfig.json":           `{"compilerOptions":{"baseUrl":".","paths":{"m":["packages/m/src/index.js"]}}}`,
			"packages/m/package.json": `{"name":"m","exports":{".":{"development":"./dist/dev.js","default":"./src/index.js"}}}`,
			"packages/m/src/index.js": "function parse(s) { return s; }\nmodule.exports = { parse };\n",
		}},
		{"literal import() of an installed package a tsconfig paths alias shadows", `
async function load(s) { const m = await import('cfg'); return m.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"tsconfig.json":                 `{"compilerOptions":{"baseUrl":".","paths":{"cfg":["plugins/index.js"]}}}`,
			"node_modules/cfg/package.json": `{"name":"cfg","exports":{".":{"development":"./dev.js","default":"./prod.js"}}}`,
			"node_modules/cfg/dev.js":       "const j = require('json5');\nexports.parse = (s) => j.parse(s);\n",
		}},
		{"literal import() of a self-reference a tsconfig paths alias shadows", `
async function load(s) { const m = await import('fixture'); return m.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json":  `{"name":"fixture","dependencies":{"json5":"2.2.1"},"exports":{".":{"development":"./dist/dev.js","default":"./plugins/index.js"}}}`,
			"tsconfig.json": `{"compilerOptions":{"baseUrl":".","paths":{"fixture":["plugins/index.js"]}}}`,
		}},
		{"literal import() of an imports entry mapped to a workspace member a tsconfig paths alias shadows", `
async function load(s) { const m = await import('#m'); return m.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json":            `{"name":"fixture","workspaces":["packages/*"],"dependencies":{"json5":"2.2.1"},"imports":{"#m":"m"}}`,
			"tsconfig.json":           `{"compilerOptions":{"baseUrl":".","paths":{"m":["packages/m/src/index.js"]}}}`,
			"packages/m/package.json": `{"name":"m","exports":{".":{"development":"./dist/dev.js","default":"./src/index.js"}}}`,
			"packages/m/src/index.js": "function parse(s) { return s; }\nmodule.exports = { parse };\n",
		}},
		{"require reached by a string key", `
const j = module['require']('json5');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Module._load", `
const j = module.constructor._load('json5', module);
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"process.dlopen", `
const m = { exports: {} };
process.dlopen(m, './x.node');
function load(s) { return m.exports.parse(s); }
load(process.argv[2]);
`, nil},
		{"eval", `
function load(s) { return eval('require')('json5').parse(s); }
load(process.argv[2]);
`, nil},
		{"new Function", `
const f = new Function('m', 'return require(m)');
function load(s) { return f('json5').parse(s); }
load(process.argv[2]);
`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, edges := gateStoreFromJS(t, tc.src, tc.files)
			if edges == 0 {
				t.Fatalf("program must have call edges")
			}
			if reason, ok := undeterminedReason(store, "a1", json5Package); !ok || reason != report.ReasonAnalysisDidNotRun {
				t.Errorf("undeterminedReason = (%q, %v); want (%q, true): not_exploitable would stand", reason, ok, report.ReasonAnalysisDidNotRun)
			}
		})
	}
}

// TestUndeterminedReason_JSFirstPartyOnlyCanRefute is the control: a program that loads
// nothing outside the tree passes the gate, so the test above detects a refutable result.
func TestUndeterminedReason_JSFirstPartyOnlyCanRefute(t *testing.T) {
	store, _ := gateStoreFromJS(t, `
function parse(s) { return s.trim(); }
function load(s) { return parse(s); }
load(process.argv[2]);
`, nil)
	if reason, ok := undeterminedReason(store, "a1", json5Package); ok {
		t.Errorf("undeterminedReason = (%q, true); want refutable", reason)
	}
}

// TestUndeterminedReason_JSScopedLimits runs programs whose package limits are scoped
// through the gate. A scoped limit holds every advisory for a package in its Targets (the
// package's resolution reach) and lets an advisory for a package outside them refute; a
// limit no package accounts for, or one the lock cannot bound, holds every advisory.
func TestUndeterminedReason_JSScopedLimits(t *testing.T) {
	// express and qs are declared; json5 is hoisted and declared by neither package. zed is
	// not installed, so nothing this lock installs can reach it.
	const lock = `{"lockfileVersion":3,"packages":{
"":{"name":"fixture","dependencies":{"express":"4.18.2","qs":"6.0.0","json5":"2.2.1"}},
"node_modules/express":{"version":"4.18.2","dependencies":{"qs":"6.0.0"}},
"node_modules/qs":{"version":"6.0.0"},
"node_modules/json5":{"version":"2.2.1"}}}`
	const brokenLock = `{"lockfileVersion":3,"packages":{
"":{"name":"fixture","dependencies":{"qs":"6.0.0"}},
"node_modules/qs":{"version":"6.0.0","dependencies":{"missing":"1.0.0"}}}}`
	const peerLock = `{"lockfileVersion":3,"packages":{
"":{"name":"fixture","dependencies":{"qs":"6.0.0"}},
"node_modules/qs":{"version":"6.0.0","peerDependencies":{"missing":"1.0.0"}}}}`
	// cfg's development export is the only file that loads json5, which cfg does not declare.
	const cfgLock = `{"lockfileVersion":3,"packages":{
"":{"name":"fixture","dependencies":{"cfg":"1.0.0","json5":"2.2.1"}},
"node_modules/cfg":{"version":"1.0.0"},
"node_modules/json5":{"version":"2.2.1"}}}`
	var (
		express = &report.Package{Ecosystem: "npm", Name: "express", Version: "4.18.2", PURL: "pkg:npm/express@4.18.2"}
		qs      = &report.Package{Ecosystem: "npm", Name: "qs", Version: "6.0.0", PURL: "pkg:npm/qs@6.0.0"}
		zed     = &report.Package{Ecosystem: "npm", Name: "zed", Version: "1.0.0", PURL: "pkg:npm/zed@1.0.0"}
	)
	cases := []struct {
		name      string
		src       string
		lock      string
		files     map[string]string // further files beside index.js
		edge      string            // a boundary node the program must have an edge into
		held      []*report.Package
		refutable []*report.Package
	}{
		{
			name: "a boundary edge into X holds X and lets a package outside X's reach refute",
			src: `const express = require('express');
const app = express();
app.get('/go', route);
function route(req, res) { res.redirect(req.query.u); }
`,
			lock:      lock,
			edge:      "npm:express#response.redirect",
			held:      []*report.Package{express, qs, json5Package},
			refutable: []*report.Package{zed},
		},
		{
			name: "a boundary edge into X through a function-local require and a derived value",
			src: `function serve() { const express = require('express'); const app = express(); app.listen(3000); }
serve();
`,
			lock:      lock,
			edge:      "npm:express#<call>.listen",
			held:      []*report.Package{express},
			refutable: []*report.Package{zed},
		},
		{
			name: "a boundary edge into X through a function-local require binding",
			src: `function go(u) { const q = require('qs'); return q.parse(u); }
go(process.argv[2]);
`,
			lock:      lock,
			edge:      "npm:qs#parse",
			held:      []*report.Package{qs},
			refutable: []*report.Package{zed},
		},
		{
			// The one boundary edge the loads do not already account for: routers in two modules
			// register the handler, so no single load bounds the express it runs under.
			name: "a handler routers in two modules register holds every advisory",
			src: `const express = require('express');
const app = express();
const { route } = require('./route');
app.get('/a', route);
require('./admin');
`,
			lock: lock,
			files: map[string]string{
				"route.js": "function route(req, res) { res.redirect(req.query.u); }\nmodule.exports = { route };\n",
				"admin.js": "const express = require('express');\nconst r = express.Router();\nconst { route } = require('./route');\nr.get('/b', route);\nmodule.exports = r;\n",
			},
			edge: "npm:express#response.redirect",
			held: []*report.Package{express, zed},
		},
		// Every binding the boundary resolver traces a package value through is recorded as a
		// load of its specifier first, and that load alone holds the package: these rows pin it
		// for each binding form, with no call into the binding.
		{
			name: "an ESM import binding of X with no call holds X",
			src: `import q from 'qs';
function main() {}
main();
`,
			lock:      lock,
			held:      []*report.Package{qs},
			refutable: []*report.Package{zed},
		},
		{
			name: "a destructured require binding of X with no call holds X",
			src: `const { parse } = require('qs');
function main() {}
main();
`,
			lock:      lock,
			held:      []*report.Package{qs},
			refutable: []*report.Package{zed},
		},
		{
			name: "a require binding of X with no call holds X",
			src: `const q = require('qs');
function main() {}
main();
`,
			lock:      lock,
			held:      []*report.Package{qs},
			refutable: []*report.Package{zed},
		},
		{
			name: "a function-local require binding of X with no call holds X",
			src: `function main() { const q = require('qs'); return q; }
main();
`,
			lock:      lock,
			held:      []*report.Package{qs},
			refutable: []*report.Package{zed},
		},
		{
			name: "X's limit holds an undeclared hoisted package X can require",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock:      lock,
			held:      []*report.Package{qs, json5Package},
			refutable: []*report.Package{zed},
		},
		{
			name: "a reach the lock cannot bound holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock: brokenLock,
			held: []*report.Package{qs, zed},
		},
		{
			name: "no lockfile holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			held: []*report.Package{qs, zed},
		},
		{
			name: "a required peer the lock does not install holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock: peerLock,
			held: []*report.Package{qs, zed},
		},
		{
			name: "a node_modules on disk holding a package the lock does not list holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock:  lock,
			files: map[string]string{"node_modules/zed/package.json": `{"name":"zed","version":"1.0.0"}`},
			held:  []*report.Package{qs, zed},
		},
		{
			name: "NODE_PATH set in the Dockerfile holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock:  lock,
			files: map[string]string{"Dockerfile": "FROM node:20\nENV NODE_PATH=/srv/lib\nCMD [\"node\", \"index.js\"]\n"},
			held:  []*report.Package{qs, zed},
		},
		{
			name: "NODE_OPTIONS preloading a module in the Procfile holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock:  lock,
			files: map[string]string{"Procfile": "web: NODE_OPTIONS='--require ./apm.js' node index.js\n"},
			held:  []*report.Package{qs, zed},
		},
		{
			name: "--preserve-symlinks in the start script holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock:  lock,
			files: map[string]string{"start.sh": "exec node --preserve-symlinks index.js\n"},
			held:  []*report.Package{qs, zed},
		},
		{
			name: "a Yarn PnP runtime beside the npm lock holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock:  lock,
			files: map[string]string{".pnp.cjs": "#!/usr/bin/env node\n"},
			held:  []*report.Package{qs, zed},
		},
		{
			// app/package-lock.json lists only qs, so without the check qs's reach would be {qs}
			// and zed, installed in the root node_modules every require from app/ also searches,
			// would refute.
			name: "a node_modules above the governing lock holds every advisory",
			src:  "require('./app/main.js');\n",
			files: map[string]string{
				"app/package-lock.json":         `{"lockfileVersion":3,"packages":{"":{"name":"app","dependencies":{"qs":"6.0.0"}},"node_modules/qs":{"version":"6.0.0"}}}`,
				"app/main.js":                   "const qs = require('qs');\nfunction go(u) { return qs.parse(u); }\ngo(process.argv[2]);\n",
				"node_modules/zed/package.json": `{"name":"zed","version":"1.0.0"}`,
			},
			held: []*report.Package{qs, zed},
		},
		{
			name: "a committed src/node_modules the lock does not list holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock:  lock,
			files: map[string]string{"src/node_modules/zed/index.js": "module.exports = {}\n"},
			held:  []*report.Package{qs, zed},
		},
		{
			name: "NODE_PATH in a CircleCI config holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock:  lock,
			files: map[string]string{".circleci/config.yml": "jobs:\n  build:\n    environment:\n      NODE_PATH: lib\n"},
			held:  []*report.Package{qs, zed},
		},
		{
			name: "node -r in a Dockerfile exec-form CMD holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock:  lock,
			files: map[string]string{"Dockerfile": "FROM node:20\nCMD [\"node\", \"-r\", \"./apm.js\", \"index.js\"]\n"},
			held:  []*report.Package{qs, zed},
		},
		{
			name: "module-alias with _moduleDirectories holds every advisory",
			src: `require('module-alias/register');
const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock: `{"lockfileVersion":3,"packages":{
"":{"name":"fixture","dependencies":{"module-alias":"2.2.3","qs":"6.0.0"}},
"node_modules/module-alias":{"version":"2.2.3"},
"node_modules/qs":{"version":"6.0.0"}}}`,
			files: map[string]string{
				"package.json":                    `{"name":"fixture","version":"1.0.0","_moduleDirectories":["vendor_modules"]}`,
				"vendor_modules/zed/package.json": `{"name":"zed","version":"1.0.0"}`,
			},
			held: []*report.Package{qs, zed},
		},
		{
			name: "a yarn.lock beside the npm lock holds every advisory",
			src: `const qs = require('qs');
function go(u) { return qs.parse(u); }
go(process.argv[2]);
`,
			lock:  lock,
			files: map[string]string{"yarn.lock": "# yarn lockfile v1\n"},
			held:  []*report.Package{qs, zed},
		},
		{
			// Held twice over: by cfg's limit, whose reach includes the hoisted json5, and by the
			// dynamic_import_specifier a literal import() keeps for an unmodeled condition.
			name: "a literal import() of X whose development export loads a hoisted package X does not declare",
			src: `async function load(s) { const m = await import('cfg'); return m.parse(s); }
load(process.argv[2]);
`,
			lock: cfgLock,
			files: map[string]string{
				"node_modules/cfg/package.json": `{"name":"cfg","exports":{".":{"development":"./dev.js","default":"./prod.js"}}}`,
				"node_modules/cfg/dev.js":       "const j = require('json5');\nexports.parse = (s) => j.parse(s);\n",
				"node_modules/cfg/prod.js":      "exports.parse = (s) => s;\n",
			},
			held: []*report.Package{json5Package},
		},
		{
			name: "a load no package accounts for stays run-wide",
			src: `const vm = require('vm');
function go(s) { return vm.runInNewContext(s); }
go(process.argv[2]);
`,
			lock: lock,
			held: []*report.Package{zed},
		},
		{
			name: "a computed first-party specifier stays run-wide",
			src: `function load(n) { return require(n); }
load(process.argv[2]);
`,
			lock: lock,
			held: []*report.Package{zed},
		},
		{
			name: "a first-party prefix load stays run-wide",
			src: `function load(n) { return require('./plugins/' + n); }
load(process.argv[2]);
`,
			lock: lock,
			held: []*report.Package{zed},
		},
		{
			name: "an unknown loader stays run-wide",
			src: `const j = module.constructor._load('json5', module);
function go(s) { return j.parse(s); }
go(process.argv[2]);
`,
			lock: lock,
			held: []*report.Package{zed},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			if tc.lock != "" {
				files["package-lock.json"] = tc.lock
			}
			maps.Copy(files, tc.files)
			store, cg := gateFromJS(t, tc.src, files)
			if len(cg.Edges) == 0 {
				t.Fatalf("program must have call edges")
			}
			if tc.edge != "" && !slices.ContainsFunc(cg.Edges, func(e plugin.CallEdge) bool { return e.Callee.SCIP == tc.edge }) {
				t.Fatalf("program must have an edge into %s; got %+v", tc.edge, cg.Edges)
			}
			for _, pkg := range tc.held {
				if reason, ok := undeterminedReason(store, "a1", pkg); !ok || reason != report.ReasonAnalysisDidNotRun {
					t.Errorf("%s: undeterminedReason = (%q, %v); want (%q, true): not_exploitable would stand", pkg.Name, reason, ok, report.ReasonAnalysisDidNotRun)
				}
			}
			for _, pkg := range tc.refutable {
				if reason, ok := undeterminedReason(store, "a1", pkg); ok {
					t.Errorf("%s: undeterminedReason = (%q, true); want refutable (scoped %+v)", pkg.Name, reason, cg.Partiality.Scoped)
				}
			}
		})
	}
}

// json5Package is the package the gate assesses: the dependency every program loads or could.
var json5Package = &report.Package{Ecosystem: "npm", Name: "json5", Version: "2.2.1", PURL: "pkg:npm/json5@2.2.1"}

// gateStoreFromJS writes src as index.js over a default tree (with files added or replacing
// entries), runs the JS producer over it, and stores the call graph and reachability
// partiality, run-wide and scoped, as the reachability and exposure-footprint artifacts.
func gateStoreFromJS(t *testing.T, src string, files map[string]string) (*artifact.MemStore, int) {
	t.Helper()
	store, cg := gateFromJS(t, src, files)
	return store, len(cg.Edges)
}

// gateFromJS is gateStoreFromJS returning the call graph itself.
func gateFromJS(t *testing.T, src string, files map[string]string) (*artifact.MemStore, plugin.CallGraphResult) {
	t.Helper()
	dir := t.TempDir()
	tree := map[string]string{
		"package.json":        `{"name":"fixture","version":"1.0.0","dependencies":{"json5":"2.2.1"}}`,
		"index.js":            src,
		"plugins/index.js":    "function parse(s) { return s; }\nmodule.exports = { parse };\n",
		"node_modules/.keep":  "",
		"build/Release/.keep": "",
	}
	maps.Copy(tree, files)
	for name, body := range tree {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	cg, err := jsanalysis.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	reach, err := jsanalysis.Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	store := artifact.NewMemStore()
	payload, err := json.Marshal(struct {
		Reachability plugin.ReachabilityResult `json:"reachability"`
		CallGraph    plugin.CallGraphResult    `json:"call_graph"`
	}{reach, cg})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(&artifact.Artifact{AssessmentID: "a1", Type: artifact.TypeReachability, ProducedBy: "test", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	fp := artifact.ExposureFootprintPayload{
		SchemaVersion:   artifact.ExposureFootprintSchemaVersion,
		AssessmentID:    "a1",
		PartialityFlags: reach.Partiality.Reasons,
	}
	for _, r := range reach.Partiality.Scoped {
		fp.ScopedPartiality = append(fp.ScopedPartiality, artifact.ScopedPartialityFlag{Reason: r.Reason, Package: r.Package, Path: r.Path, Targets: r.Targets})
	}
	fpPayload, err := json.Marshal(fp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(&artifact.Artifact{AssessmentID: "a1", Type: artifact.TypeExposureFootprint, ProducedBy: "test", Payload: fpPayload}); err != nil {
		t.Fatal(err)
	}
	return store, cg
}
