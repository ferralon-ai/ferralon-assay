package jsanalysis

import (
	"context"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestCallGraph_OutOfTreePackageNeverOnlyInherent pins the invariant the refutation gate
// relies on: a graph with edges whose only partiality reasons are inherent can refute, so
// a module that loads code this lane does not read, in any form, must declare a did_not_run
// reason: an out-of-tree package, a target computed at run time, or a relative module that is
// not in the tree. Where want is set, that specific reason must be among them.
func TestCallGraph_OutOfTreePackageNeverOnlyInherent(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"direct member head", map[string]string{"app.js": `
const JSON5 = require('json5');
function load(s) { return JSON5.parse(s); }
load(process.argv);
`}, ""},
		{"alias of the binding", map[string]string{"app.js": `
const lib = require('json5'); const p = lib;
function load(s) { return p.parse(s); }
load(process.argv);
`}, ""},
		{"inline require in a function", map[string]string{"app.js": `
function load(s) { return require('json5').parse(s); }
load(process.argv);
`}, ""},
		{"inline require at top level", map[string]string{"app.js": `
function run() { return 1; }
require('json5').parse(process.argv);
run();
`}, ""},
		{"destructured require", map[string]string{"app.js": `
const { parse } = require('json5');
function load(s) { return parse(s); }
load(process.argv);
`}, ""},
		{"binding passed as a value", map[string]string{"app.js": `
const JSON5 = require('json5');
function apply(f, s) { return f(s); }
function load(s) { return apply(JSON5.parse, s); }
load(process.argv);
`}, ""},
		{"ESM default", map[string]string{"app.js": `
import JSON5 from 'json5';
function load(s) { return JSON5.parse(s); }
load(process.argv);
`}, ""},
		{"ESM named", map[string]string{"app.js": `
import { parse } from 'json5';
function load(s) { return parse(s); }
load(process.argv);
`}, ""},
		{"ESM namespace", map[string]string{"app.js": `
import * as J from 'json5';
function load(s) { return J.parse(s); }
load(process.argv);
`}, ""},
		{"ESM side-effect import", map[string]string{"app.js": `
import 'json5';
function load(s) { return s; }
load(process.argv);
`}, ""},
		{"dynamic import with a literal", map[string]string{"app.js": `
async function load(s) { const J = await import('json5'); return J.parse(s); }
load(process.argv);
`}, ""},
		{"TS import-equals", map[string]string{"app.ts": `
import JSON5 = require('json5');
function load(s: string) { return JSON5.parse(s); }
load(process.argv[2]);
`}, ""},
		{"named re-export", map[string]string{
			"lib.js": "export { parse } from 'json5';\n",
			"app.js": `
import { parse } from './lib';
function load(s) { return parse(s); }
load(process.argv);
`}, ""},
		{"star re-export", map[string]string{
			"lib.js": "export * from 'json5';\n",
			"app.js": `
import { parse } from './lib';
function load(s) { return parse(s); }
load(process.argv);
`}, ""},
		{"subpath import mapped to a package", map[string]string{
			"package.json": `{"name":"app","imports":{"#json":"json5"}}`,
			"app.js": `
import { parse } from '#json';
function load(s) { return parse(s); }
load(process.argv);
`}, ""},
		{"require aliased", map[string]string{"app.js": `
const r = require;
function load(s) { return r('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require passed as an argument", map[string]string{"app.js": `
function load(s, req) { return req('json5').parse(s); }
load(process.argv, require);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"module.require aliased", map[string]string{"app.js": `
const r = module.require.bind(module);
function load(s) { return r('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require.main.require", map[string]string{"app.js": `
function load(s) { return require.main.require('json5').parse(s); }
load(process.argv);
`}, ""},
		{"createRequire result called with a literal", map[string]string{"app.js": `
const req = module.constructor.createRequire(__filename);
function load(s) { return req('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonUninspectablePackage},
		{"createRequire result called inline", map[string]string{"app.js": `
function load(s) { return module.constructor.createRequire(__filename)('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonUninspectablePackage},
		{"createRequire result aliased", map[string]string{"app.js": `
const req = module.constructor.createRequire(__filename); const r = req;
function load(s) { return r('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"createRequire result called with a variable", map[string]string{"app.js": `
const req = module.constructor.createRequire(__filename);
function load(s, n) { return req(n).parse(s); }
load(process.argv, 'json5');
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"createRequire itself aliased", map[string]string{"app.js": `
const mk = module.constructor.createRequire;
function load(s) { return mk(__filename)('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require of a concatenated literal", map[string]string{
			"plugins/index.js": "function run(s) { return s; }\nmodule.exports = { run };\n",
			"app.js": `
function load(s, n) { return require('./plugins/' + n).run(s); }
load(process.argv, 'json5');
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require of an interpolated template", map[string]string{"app.js": `
function load(s, n) { return require(` + "`./${n}`" + `).parse(s); }
load(process.argv, 'json5');
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"dynamic import of an interpolated template", map[string]string{"app.js": `
async function load(s, n) { const J = await import(` + "`./${n}`" + `); return J.parse(s); }
load(process.argv, 'json5');
`}, plugin.PartialReasonDynamicImportSpecifier},
		{"native addon", map[string]string{"app.js": `
const addon = require('./build/Release/x.node');
function load(s) { return addon.parse(s); }
load(process.argv);
`}, plugin.PartialReasonUnresolvedModule},
		{"generated module absent from the tree", map[string]string{"app.js": `
import { parse } from './dist/gen';
function load(s) { return parse(s); }
load(process.argv);
`}, plugin.PartialReasonUnresolvedModule},
		{"absolute specifier", map[string]string{"app.js": `
const gen = require('/opt/gen/x.js');
function load(s) { return gen.parse(s); }
load(process.argv);
`}, ""},
		{"require inside a typeof test", map[string]string{"app.js": `
function load(s) { if (typeof require('json5').parse === 'function') return s; return s; }
load(process.argv);
`}, plugin.PartialReasonUninspectablePackage},
		{"imports entry whose require branch is a package", map[string]string{
			"package.json": `{"name":"app","imports":{"#j":{"import":"./esm.js","require":"json5"}}}`,
			"esm.js":       "export function parse(s) { return s; }\n",
			"app.js": `
const j = require('#j');
function load(s) { return j.parse(s); }
load(process.argv);
`}, plugin.PartialReasonUninspectablePackage},
		{"imports entry whose node branch precedes import", map[string]string{
			"package.json": `{"name":"app","imports":{"#j":{"node":"json5","import":"./esm.js"}}}`,
			"esm.js":       "export function parse(s) { return s; }\n",
			"app.js": `
import { parse } from '#j';
function load(s) { return parse(s); }
load(process.argv);
`}, plugin.PartialReasonUninspectablePackage},
		{"workspace member whose require branch is not in the tree", map[string]string{
			"package.json":            `{"name":"root","workspaces":["packages/*"]}`,
			"packages/m/package.json": `{"name":"m","exports":{".":{"import":"./src/index.js","require":"./lib/index.cjs"}}}`,
			"packages/m/src/index.js": "export function parse(s) { return s; }\n",
			"app.js": `
const m = require('m');
function load(s) { return m.parse(s); }
load(process.argv);
`}, plugin.PartialReasonUninspectablePackage},
		{"workspace member whose main is not in the tree", map[string]string{
			"package.json":            `{"name":"root","workspaces":["packages/*"]}`,
			"packages/m/package.json": `{"name":"m","main":"./lib/index.cjs"}`,
			"packages/m/index.js":     "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js": `
const m = require('m');
function load(s) { return m.parse(s); }
load(process.argv);
`}, plugin.PartialReasonUninspectablePackage},
		{"require reached by a string key", map[string]string{"app.js": `
const j = module['require']('json5');
function load(s) { return j.parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"module indexed by a computed key", map[string]string{"app.js": `
const k = 'require';
function load(s) { return module[k]('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"Module._load", map[string]string{"app.js": `
const j = module.constructor._load('json5', module);
function load(s) { return j.parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"process.dlopen", map[string]string{"app.js": `
const m = { exports: {} };
process.dlopen(m, './x.node');
function load(s) { return m.exports.parse(s); }
load(process.argv);
`}, plugin.PartialReasonUnresolvedModule},
		{"eval", map[string]string{"app.js": `
function load(s) { return eval('require')('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"eval through globalThis", map[string]string{"app.js": `
const run = globalThis.eval;
function load(s) { return run('require')('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"new Function", map[string]string{"app.js": `
const f = new Function('m', 'return require(m)');
function load(s) { return f('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function aliased", map[string]string{"app.js": `
const F = Function;
function load(s) { return F('m', 'return require(m)')('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeProgram(t, tc.files)})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if len(res.Edges) == 0 {
				t.Fatalf("fixture must have edges, so the gate's zero-edge arm cannot be what holds it undetermined")
			}
			if !hasDidNotRun(res.Partiality) {
				t.Errorf("unread code declared only %v; want a did_not_run reason", res.Partiality.Reasons)
			}
			if tc.want != "" && !slices.Contains(res.Partiality.Reasons, tc.want) {
				t.Errorf("reasons = %v; want %s among them", res.Partiality.Reasons, tc.want)
			}
		})
	}
}

// TestCallGraph_InTreeOnlyDeclaresNoDidNotRun is the control: in-tree loads (including a
// TS sibling imported by its emitted .js name and an imports entry whose runtime branches
// all stay in the tree), a JSON file, require.resolve, a typeof test, a Function type
// annotation, a property named eval and an unresolved local call leave the graph with inherent reasons only, so the invariant
// above is not met by declaring did_not_run on every module.
func TestCallGraph_InTreeOnlyDeclaresNoDidNotRun(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"util.js":      "function trim(s) { return s.trim(); }\nmodule.exports = { trim };\n",
		"fmt.ts":       "export function fmt(s: string, cb?: Function) { return s; }\nconst bind = Function.prototype.bind;\n",
		"config.json":  `{"a": 1}`,
		"package.json": `{"name": "app", "imports": {"#u": {"import": "./util.js", "require": "./util.js", "types": "./util.d.ts"}}}`,
		"app.js": `
const { trim } = require('./util');
import './util';
import { fmt } from './fmt.js';
const u = require('#u');
const cfg = require('./config.json');
const where = require.resolve('./util');
if (typeof require === 'function' && cfg.eval) { load(where); }
module.exports = { load };
function load(s) { return fmt(trim(s)); }
load(process.argv);
`,
	})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if len(res.Edges) == 0 {
		t.Fatalf("control must have edges; got none")
	}
	if hasDidNotRun(res.Partiality) {
		t.Errorf("in-tree only program declared %v; want inherent reasons only", res.Partiality.Reasons)
	}
}

func hasDidNotRun(p plugin.Partiality) bool {
	for _, r := range p.Reasons {
		if report.ClassifyPartialityReason(r) == report.PartialityDidNotRun {
			return true
		}
	}
	return false
}
