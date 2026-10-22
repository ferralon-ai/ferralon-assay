package trigger

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
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

// TestUndeterminedReason_JSStylesheetImport: a stylesheet import loads no unread code only with
// a stylesheet extension, a regular file in the tree, a stock Create React App importing it from
// its src directory, and no bundler, transform, hook or package override in the tree. A program
// that does nothing else can then refute an advisory on any package but the loader runtime's; one
// that also loads unread code is still held, and so is each program missing one of the conditions.
func TestUndeterminedReason_JSStylesheetImport(t *testing.T) {
	const body = "function parse(s) { return s.trim(); }\nfunction load(s) { return parse(s); }\nload(process.argv[2]);\n"
	const css = "body { margin: 0; }\n"
	cra := func(extra map[string]string) map[string]string {
		files := map[string]string{
			".git/HEAD":    "ref: refs/heads/main\n",
			"package.json": `{"name":"app","private":true,"dependencies":{"json5":"2.2.1","react-scripts":"5.0.1"},"scripts":{"start":"react-scripts start","build":"react-scripts build"}}`,
		}
		maps.Copy(files, extra)
		return files
	}
	styleLoader := &report.Package{Ecosystem: "npm", Name: "style-loader", Version: "3.3.1", PURL: "pkg:npm/style-loader@3.3.1"}
	// src is written as src/index.js, which react-scripts compiles, unless root is set; the root
	// index.js then holds src in place of body.
	cases := []struct {
		name  string
		src   string
		root  bool
		files map[string]string
		pkg   *report.Package // json5Package when nil
		held  bool
	}{
		{"an in-tree stylesheet in a stock Create React App and nothing else unread", "import './index.css';\n" + body, false,
			cra(map[string]string{"src/index.css": css}), nil, false},
		{"an advisory on the stylesheet loader runtime", "import './index.css';\n" + body, false,
			cra(map[string]string{"src/index.css": css}), styleLoader, true},
		{"an in-tree stylesheet outside a Create React App", "import './index.css';\n" + body, false,
			map[string]string{"src/index.css": css}, nil, true},
		{"an in-tree stylesheet imported from outside the app's src", "import './index.css';\n" + body, true,
			cra(map[string]string{"index.css": css}), nil, true},
		{"an in-tree stylesheet beside a native addon", "import './index.css';\nconst addon = require('../build/Release/x.node');\n" + body + "addon.parse(process.argv[2]);\n", false,
			cra(map[string]string{"src/index.css": css}), nil, true},
		{"an in-tree asset that is not a stylesheet", "import './logo.svg';\n" + body, false,
			cra(map[string]string{"src/logo.svg": "<svg/>\n"}), nil, true},
		{"a stylesheet absent from the tree", "import './index.css';\n" + body, false, cra(nil), nil, true},
		{"an in-tree stylesheet under a custom webpack rule for .css", "import './index.css';\n" + body, false,
			cra(map[string]string{"src/index.css": css, "webpack.config.js": "module.exports = { module: { rules: [{ test: /\\.css$/, use: './css-loader.js' }] } };\n"}), nil, true},
		{"an in-tree stylesheet beside a pnpm patch of a dependency", "import './index.css';\n" + body, false,
			cra(map[string]string{"src/index.css": css, "pnpm-workspace.yaml": "patchedDependencies:\n  json5@2.2.1: patches/json5.patch\n"}), nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rootSrc, files := body, maps.Clone(tc.files)
			if tc.root {
				rootSrc = tc.src
			} else {
				files["src/index.js"] = tc.src
			}
			store, edges := gateStoreFromJS(t, rootSrc, files)
			if edges == 0 {
				t.Fatalf("program must have call edges")
			}
			pkg := tc.pkg
			if pkg == nil {
				pkg = json5Package
			}
			reason, ok := undeterminedReason(store, "a1", pkg)
			if tc.held && (!ok || reason != report.ReasonAnalysisDidNotRun) {
				t.Errorf("undeterminedReason = (%q, %v); want (%q, true)", reason, ok, report.ReasonAnalysisDidNotRun)
			}
			if !tc.held && ok {
				t.Errorf("undeterminedReason = (%q, true); want refutable", reason)
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
	return store, len(cg.Edges)
}

// TestUndeterminedReason_JSLexerHidesNoCode runs programs whose only unread load sits where the
// lexer once blanked code: inside a template substitution, or after a quote, backtick or comment
// opener the lexer misread as starting a literal. Each held program must declare; each control,
// whose require text really is inside a literal, must stay refutable. Sources write a backtick
// as '^'.
func TestUndeterminedReason_JSLexerHidesNoCode(t *testing.T) {
	const tail = "function load(s) { return m.parse(s); }\nload(process.argv[2]);\n"
	cases := []struct {
		name string
		src  string
		held bool
	}{
		{"require inside a template substitution", `
function load(s) { return ^${require(process.argv[3]).parse(s)}^; }
load(process.argv[2]);
`, true},
		{"eval inside a template substitution", `
function load(s) { return ^v=${eval(s)}^; }
load(process.argv[2]);
`, true},
		{"dynamic import inside a template substitution", `
function load(s) { return ^${import(s)}^; }
load(process.argv[2]);
`, true},
		{"require inside a nested template", `
function load(s) { return ^a${^b${require(process.argv[3]).parse(s)}^}^; }
load(process.argv[2]);
`, true},
		{"require after a block and a brace in a string inside a substitution", `
function load(s) { return ^${[s].map(x => { return '}' + x; }).join() + require(process.argv[3]).parse(s)}^; }
load(process.argv[2]);
`, true},
		{"regex holding a quote after return", `
function check(s) { return /'/.test(s); }
const m = require(process.argv[3]); // it's dynamic
` + tail, true},
		{"regex holding a quote after a control condition", `
function check(s) { if (s) /'/.test(s); return s; }
const m = require(process.argv[3]); // it's dynamic
` + tail, true},
		{"division after a postfix increment", `
let i = 0;
const n = i++ / 2; const m = require(process.argv[3]); // c
` + tail, true},
		{"JSX text with apostrophes", `
function A() {
  return <p>Don't panic</p>;
}
const m = require(process.argv[3]);
function B() {
  return <p>That's all</p>;
}
` + tail, true},
		{"JSX closing tag followed by code on the same line", `
const A = () => <p>hi</p>; const m = require(process.argv[3]); // c
` + tail, true},
		{"a backtick in JSX text that never closes", `
const A = () => <p>Press ^ to search</p>;
const m = require(process.argv[3]);
` + tail, true},
		{"a comment opener in JSX text that never closes", `
const A = () => <p>Match files with /* globs</p>;
const m = require(process.argv[3]);
` + tail, true},
		{"a stray backtick in JSX text paired with a later template", `
const A = () => <p>Run ^npm i</p>;
const m = require(process.argv[3]);
function B() { return ^ok^; }
` + tail, true},
		{"a stray comment opener in JSX text paired with a later comment", `
function A() {
  return <p>src/*</p>;
}
const m = require(process.argv[3]);
function B() {
  /* parse it */
  return null;
}
` + tail, true},
		{"require tagging a template flush against it", `
const m = require^json5^;
` + tail, true},
		{"Function tagging a template flush against it", `
const m = Function^return require(process.argv[3])^();
` + tail, true},
		{"JSX apostrophe followed by a require on its line", `
function A(name) { return <p>Don't forget {require(process.argv[3]).parse(name)}</p>; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"JSX apostrophe followed by an eval on its own line", `
function A(x) {
  return (
    <div>
      <p>It's {eval(x)}</p>
    </div>
  );
}
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"a stray backtick in JSX text inverting a template that holds an apostrophe", `
const A = () => <p>Press ^ to search</p>;
function B(x) { return ^it's ${require(x)}^; }
function parse(s) { return s.trim(); }
function load(s) { return parse(s); }
load(process.argv[2]);
`, true},
		{"URL text in JSX followed by an import on its line", `
const A = () => <p>See http://example.com {import(process.argv[3])}</p>;
function parse(s) { return s.trim(); }
function load(s) { return parse(s); }
load(process.argv[2]);
`, true},
		{"regex holding a quote after a block", `
function check(s) { if (s) { s = s.trim(); } /'/.test(s); const m = require(process.argv[3]); return m; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		// Template and comment text shaped like a loader call is read as code, since a
		// misread opener can make real code look like text; these over-declare by design.
		{"loader-call text in a template's literal part", `
function load(s) { return ^require(process.argv[3]) ${s}^; }
load(process.argv[2]);
`, true},
		{"loader-call text in a multi-line template holding quotes", `
function load(s) { return ^it's line one
require(process.argv[3]) "here"
and ${s.trim()} done^; }
load(process.argv[2]);
`, true},
		{"paired backticks in JSX text", `
const A = () => <p>Run ^npm i^ first</p>;
function load(s) { return s.trim(); }
load(process.argv[2]);
`, false},
		{"JSDoc types and prose naming loaders", `
/**
 * Loads it. Function that this returns is safe to require.
 * @param {Function|import('x').T} s the text
 */
function load(s) { return s.trim(); }
load(process.argv[2]);
`, false},
		{"string continued across a line", `
function load(s) { return 'a \
require(process.argv[3]) b' + s.trim(); }
load(process.argv[2]);
`, false},
		{"regex holding a quote and a backtick after return", `
function load(s) { return /[^'"]/.test(s) ? s.trim() : s; }
load(process.argv[2]);
`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, edges := gateStoreFromJS(t, strings.ReplaceAll(tc.src, "^", "`"), nil)
			if edges == 0 {
				t.Fatalf("program must have call edges")
			}
			reason, ok := undeterminedReason(store, "a1", json5Package)
			if tc.held && (!ok || reason != report.ReasonAnalysisDidNotRun) {
				t.Errorf("undeterminedReason = (%q, %v); want (%q, true): not_exploitable would stand", reason, ok, report.ReasonAnalysisDidNotRun)
			}
			if !tc.held && ok {
				t.Errorf("undeterminedReason = (%q, true); want refutable", reason)
			}
		})
	}
}
