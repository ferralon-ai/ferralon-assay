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
`}, plugin.PartialReasonEvaluatedCode}, {"require.call", map[string]string{"app.js": `
function load(s, n) { return require.call(null, n).parse(s); }
load(process.argv, 'json5');
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"module.require with a variable", map[string]string{"app.js": `
function load(s, n) { return module.require(n).parse(s); }
load(process.argv, 'json5');
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"module.require tested then called with a variable", map[string]string{"app.js": `
function load(s, n) { return (module.require && module.require(n)).parse(s); }
load(process.argv, 'json5');
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require tested then handed on", map[string]string{"app.js": `
const r = typeof require === 'function' && require;
function load(s) { return r('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require as a ternary branch", map[string]string{"app.js": `
const r = require.main === module ? require : null;
function load(s) { return r('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require as a parameter default", map[string]string{"app.js": `
function load(s, r = require) { return r('json5').parse(s); }
load(process.argv);
function main(a) { return load(a); }
main(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require parameter called with a variable", map[string]string{"app.js": `
function load(s, require, n) { return require(n).parse(s); }
load(process.argv, null, 'json5');
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"arrow require parameter called with a variable", map[string]string{"app.js": `
const load = (s, require, n) => require(n).parse(s);
load(process.argv, null, 'json5');
function main(a) { return load(a); }
main(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"declared require called with a variable", map[string]string{"app.js": `
function require(n) { return n; }
function load(s, n) { return require(n).parse(s); }
load(process.argv, 'json5');
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require passed to a call in a parameter-shaped position", map[string]string{"app.js": `
function load(s) { return s; }
const r = wrap(require, load);
function wrap(a, b) { return a('json5'); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require destructured from module", map[string]string{"app.js": `
const { require: r } = module;
function load(s) { return r('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require in an object literal", map[string]string{"app.js": `
const o = { require: require };
function load(s) { return o.require('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"indirect eval", map[string]string{"app.js": `
function load(s) { return (0, eval)('require')('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call constructs", map[string]string{"app.js": `
function load(s) { return Function.call(null, 'm', 'return require(m)')('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.apply constructs", map[string]string{"app.js": `
function load(s) { return Function.apply(null, ['m', 'return require(m)'])('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.bind constructs", map[string]string{"app.js": `
function load(s) { return Function.bind(null, 'm', 'return require(m)')()('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function optional call", map[string]string{"app.js": `
function load(s) { return Function?.('m', 'return require(m)')('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function passed as an argument", map[string]string{"app.js": `
function load(s) { return Reflect.construct(Function, ['m', 'return require(m)'])('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function as call receiver argument", map[string]string{"app.js": `
function load(s) { return Function.call.call(Function, null, 'm', 'return require(m)')('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global alias eval", map[string]string{"app.js": `
const g = globalThis;
function load(s) { return g.eval(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global computed key", map[string]string{"app.js": `
function load(k, s) { return globalThis[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global alias concatenated key", map[string]string{"app.js": `
const g = globalThis;
function load(s) { return g['ev' + 'al'](s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global alias Function", map[string]string{"app.js": `
const g = globalThis;
function load(s) { return g.Function(s)(); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global alias chain", map[string]string{"app.js": `
var freeGlobal = typeof global == 'object' && global;
var root = freeGlobal || self;
function load(k, s) { return root[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global optional computed key", map[string]string{"app.js": `
function load(k, s) { return window?.[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function return this then require", map[string]string{"app.js": `
function load(m) { return Function('return this')().require(m); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function return this then eval", map[string]string{"app.js": `
const g = Function('return this')();
function load(s) { return g.eval(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function return this then computed key", map[string]string{"app.js": `
const g = Function('return this')();
function load(m) { return g['req' + 'uire'](m); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function return this then Function", map[string]string{"app.js": `
const g = Function('return this')();
function load(s) { return g.Function(s)(); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function return this then computed key inline", map[string]string{"app.js": `
function load(k, s) { return Function('return this')()[k](s); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"new Function return this then eval", map[string]string{"app.js": `
function load(s) { return new Function('return this')().eval(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function returning this called later", map[string]string{"app.js": `
const f = Function('return this');
function load(k, s) { return f()[k](s); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function returning a global name called later", map[string]string{"app.js": `
const f = Function('return globalThis');
function load(k, s) { return f()[k](s); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function returning eval", map[string]string{"app.js": `
function load(s) { return Function('return eval')()(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function returning require", map[string]string{"app.js": `
function load(m) { return Function('return require')()(m); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function returning Function", map[string]string{"app.js": `
function load(s) { return Function('return Function')()(s)(); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function returning arguments", map[string]string{"app.js": `
const f = Function('a', 'return arguments');
function load(s) { return f(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body constructs", map[string]string{"app.js": `
const f = Function('C', 'return new C');
function load(C) { return f(C); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body calls a parameter", map[string]string{"app.js": `
const f = Function('s', 'return s()');
function load(s) { return f(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body reads a member", map[string]string{"app.js": `
const f = Function('o', 'return o.x');
function load(o) { return f(o); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body indexes", map[string]string{"app.js": `
const f = Function('o', 'return o[0]');
function load(o) { return f(o); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body tags a template", map[string]string{"app.js": `
const f = Function('t', 'return t` + "`" + `` + "`" + `');
function load(t) { return f(t); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body assigns a global", map[string]string{"app.js": `
Function('x = globalThis')();
function load(k, s) { return x[k](s); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body shifts into a global", map[string]string{"app.js": `
Function('x <<= 1')();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body increments a global", map[string]string{"app.js": `
Function('x++')();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function parameter default", map[string]string{"app.js": `
const f = Function('a = 1', 'return a');
function load(s) { return f(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function parameter named eval", map[string]string{"app.js": `
const f = Function('eval', 'return 1');
function load(s) { return f(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function literal with an escape", map[string]string{"app.js": `
const f = Function('a', 'return \\x61');
function load(s) { return f(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body concatenated", map[string]string{"app.js": `
const f = Function('a', 'return ' + 'a');
function load(s) { return f(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body a template", map[string]string{"app.js": `
const f = Function('a', ` + "`" + `return a` + "`" + `);
function load(s) { return f(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body a variable", map[string]string{"app.js": `
function load(a, s) { return Function('a', s)(a); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global require read", map[string]string{"app.js": `
const r = globalThis.require;
function load(m) { return r(m); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global into an IIFE that reads arguments", map[string]string{"app.js": `
function load(k, s) {
  return (function (g) { const h = arguments[0]; return h[k](s); })(globalThis);
}
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name assigned without a declaration", map[string]string{"app.js": `
self = make();
function make() { return {}; }
function load(k, s) { return self[k](s); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global awaited into an alias", map[string]string{"app.js": `
async function load(k, s) { const g = await globalThis; return g[k](s); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global before || into an alias", map[string]string{"app.js": `
const g = globalThis || {};
function load(k, s) { return g[k](s); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global non-null asserted into an alias", map[string]string{"app.ts": `
const g = globalThis!;
function load(k: string, s: string) { return (g as any)[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name read before its top-level var", map[string]string{"app.js": `
self[process.argv[2]](process.argv[3]);
var self = make();
function make() { return {}; }
`}, plugin.PartialReasonEvaluatedCode},
		{"global as a ternary branch", map[string]string{"app.js": `
function use(o) { return o; }
function load(c) { return use(c ? globalThis : null); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"this optional computed call in a plain function", map[string]string{"app.js": `
function load(k, s) { return this[k]?.(s); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global before || as an argument", map[string]string{"app.js": `
function use(o) { return o; }
function load() { return use(globalThis || {}); }
load();
`}, plugin.PartialReasonEvaluatedCode},
		{"global returned in an array", map[string]string{"app.js": `
function load() { return [globalThis]; }
load();
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this in a block after a parenthesized expression", map[string]string{"app.js": `
var y = (1)
{ this[process.argv[2]](process.argv[3]); }
function load() { return y; }
load();
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this in a try block", map[string]string{"app.js": `
try { this[process.argv[2]](process.argv[3]); } catch (e) { load(); }
function load() { return 1; }
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this handed on", map[string]string{"app.js": `
function use(o) { return o; }
use(this);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body constructs, called at once", map[string]string{"app.js": `
function load() { Function('new Date')(); }
load();
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body reads a member, called at once", map[string]string{"app.js": `
function load() { Function('this.x')(); }
load();
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body tags a template, called at once", map[string]string{"app.js": `
function load() { Function('x` + "`" + `` + "`" + `')(); }
load();
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body decrements a global, called at once", map[string]string{"app.js": `
function load() { Function('x--')(); }
load();
`}, plugin.PartialReasonEvaluatedCode},
		{"Function returning require, called at once", map[string]string{"app.js": `
function load(m) { const r = Function('return require')(); r(m); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function returning Function, called at once", map[string]string{"app.js": `
function load(s) { const F = Function('return Function')(); F(s)(); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body reads arguments, called at once", map[string]string{"app.js": `
function load(s) { Function('a', 'arguments')(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body with an escape, called at once", map[string]string{"app.js": `
function load() { Function('this\x5b"ev"+"al"\x5d\x28"1"\x29')(); }
load();
`}, plugin.PartialReasonEvaluatedCode},
		{"Function parameter with a default expression", map[string]string{"app.js": `
const f = Function('a = this["ev" + "al"]("1")', 'return 1');
function load() { return f(); }
load();
`}, plugin.PartialReasonEvaluatedCode},
		{"new Function result handed on", map[string]string{"app.js": `
function use(o) { return o; }
function load() { use(new Function('return this')()); }
load();
`}, plugin.PartialReasonEvaluatedCode},
		{"global after a spread argument", map[string]string{"app.js": `
function load(k, s) {
  return (function (a, g) { return a[k](s); })(...[], globalThis);
}
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name of a function expression stays inside it", map[string]string{"app.js": `
const f = function self() { return 1; };
function load(k, s) { f(); return self[k](s); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global alias in parentheses", map[string]string{"app.js": `
const g = (globalThis);
function load(k, s) { return g[k](s); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"this in an anonymous generator", map[string]string{"app.js": `
const load = function* (k, s) { yield this[k](s); };
load(process.argv, process.argv).next();
`}, plugin.PartialReasonEvaluatedCode},
		{"this in a named generator", map[string]string{"app.js": `
function* load(k, s) { yield this[k](s); }
load(process.argv, process.argv).next();
`}, plugin.PartialReasonEvaluatedCode},
		{"global name renamed away by an import", map[string]string{"util.js": "export const self = 1;\n", "app.js": `
import { self as me } from './util.js';
function load(k, s) { return me + self[k](s); }
load(process.argv, process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"eval on any receiver", map[string]string{"app.js": `
function load(o, s) { return o.eval(s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function on any receiver", map[string]string{"app.js": `
function load(o, s) { return o.Function(s)(); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"this in a plain function", map[string]string{"app.js": `
function load(k, s) { return this[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"this in an IIFE", map[string]string{"app.js": `
function load(k, s) { return (function () { return this[k](s); })(); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"this in an arrow inside a plain function", map[string]string{"app.js": `
function load(k, s) { const f = () => this[k](s); return f(); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this", map[string]string{"app.js": `
const g = this;
function load(k, s) { return g[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Reflect.get on the global", map[string]string{"app.js": `
function load(k, s) { return Reflect.get(globalThis, k)(s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Reflect.apply on a global value", map[string]string{"app.js": `
function load(k, s) { return Reflect.apply(globalThis[k], null, [s]); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global handed on", map[string]string{"app.js": `
function pick(o, k) { return o[k]; }
function load(k, s) { return pick(globalThis, k)(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global call target", map[string]string{"app.js": `
function load(f, s) { return f.call(globalThis, s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global self beside a local self", map[string]string{"app.js": `
function Box() { var self = this; return self; }
function load(k, s) { return self[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"alias declared in an enclosing function", map[string]string{"app.js": `
function outer() { var g = globalThis; return function load(k, s) { return g[k](s); }; }
const load = outer();
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level var of a global name", map[string]string{"app.js": `
var self = self || {};
function load(k, s) { return self[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"local initialised from a global", map[string]string{"app.js": `
function load(k, s) { let w = typeof window !== 'undefined' ? window : global; return w[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"local self inside a block, global self after", map[string]string{"app.js": `
function load(k, s) { if (k) { let self = {}; self.x = 1; } return self[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global bound to an IIFE parameter", map[string]string{"app.js": `
var load = (function (root) { return function (k, s) { return root[k](s); }; })(this);
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global bound through call", map[string]string{"app.js": `
var load = (function (g) { return function (k, s) { return g[k](s); }; }).call(this, this);
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global bound to an IIFE that reads arguments", map[string]string{"app.js": `
var load = (function () { var g = arguments[0]; return function (k, s) { return g[k](s); }; })(globalThis);
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global passed beyond the parameters", map[string]string{"app.js": `
var load = (function (a) { return function (k, s) { return a(k, s); }; })(eval, globalThis);
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global handed to a call in an initialiser", map[string]string{"app.js": `
const g = wrap(globalThis);
function wrap(o) { return o; }
function load(k, s) { return g[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this tested then indexed", map[string]string{"app.js": `
var r = this && this[process.argv[2]](process.argv[3]);
function load(k, s) { return r; }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global into a spread IIFE", map[string]string{"app.js": `
var load = (function (g) { return function (k, s) { return g[k](s); }; })(...[globalThis]);
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global assigned to a declared name", map[string]string{"app.js": `
var g;
g = globalThis;
function load(k, s) { return g[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global assigned to an undeclared name", map[string]string{"app.js": `
g = this;
function load(k, s) { return g[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global assigned by a logical assignment", map[string]string{"app.js": `
let g;
g ??= globalThis;
function load(k, s) { return g[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global behind a type annotation", map[string]string{"app.js": `
const g: any = globalThis;
function load(k, s) { return g[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global as a destructuring default", map[string]string{"app.js": `
const { g = globalThis } = {};
function load(k, s) { return g[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global destructured from the global", map[string]string{"app.js": `
const { self: g } = globalThis;
function load(k, s) { return g[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global as a parameter default", map[string]string{"app.js": `
function load(k, s, g = globalThis) { return g[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level var of a global name read in a function", map[string]string{"app.js": `
var self = make();
function make() { return {}; }
function load(k, s) { return self[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level var of a global name assigned in a block", map[string]string{"app.js": `
if (process.env.X) { var global = {}; }
global[process.argv[2]](process.argv[3]);
function load(k, s) { return k; }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level var of window", map[string]string{"app.js": `
var window = {};
window[process.argv[2]](process.argv[3]);
function load(k, s) { return k; }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"computed key on parent", map[string]string{"app.js": `
function load(k, s) { return parent[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"computed key on frames", map[string]string{"app.js": `
function load(k, s) { return frames[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top handed on as a value", map[string]string{"app.js": `
function load(k, s) { return run(top, k, s); }
function run(g, k, s) { return g[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"alias of opener", map[string]string{"app.js": `
const g = opener;
function load(k, s) { return g[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level var of top", map[string]string{"app.js": `
var top = {};
top[process.argv[2]](process.argv[3]);
function load(k, s) { return k; }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name beside an import call", map[string]string{"app.js": `
const m = import('./m').then(String);
function load(k, s) { return self[k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name on the line after an arrow that names it", map[string]string{"app.js": `
const pick = self => self.x
self[process.argv[2]](process.argv[3])
function load(k, s) { return pick(k); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name after an arrow body in a call", map[string]string{"app.js": `
run(self => self.x, self);
function run(f, g) { return g[process.argv[2]](process.argv[3]); }
function load(k, s) { return k; }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global as an array element", map[string]string{"app.js": `
const pair = [globalThis, 1];
function load(k, s) { return pair[0][k](s); }
function main(a) { return load(a, a); }
main(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function in an array", map[string]string{"app.js": `
function load(s) { return [Function][0]('m', 'return require(m)')('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function returned", map[string]string{"app.js": `
function ctor() { return Function; }
function load(s) { return ctor()('m', 'return require(m)')('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function behind ||", map[string]string{"app.js": `
const F = globalThis.F || Function;
function load(s) { return F('m', 'return require(m)')('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function as a ternary branch", map[string]string{"app.js": `
const F = process.env.X ? Function : null;
function load(s) { return F('m', 'return require(m)')('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name bound by a for-of header, read after the loop", map[string]string{"app.js": `
for (const self of [1]) {}
var e = self.eval;
function load(s) { return e(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name bound by a for-in header, read after the loop", map[string]string{"app.js": `
const o = {};
for (let global in o) {}
const e = global.eval;
function load(s) { return e(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name bound by a for header in a function, read after the loop", map[string]string{"app.js": `
function load(s) {
  for (let self = 0; self < 1; self++) {}
  var e = self.eval;
  return e(s);
}
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name bound by a for header with a statement body", map[string]string{"app.js": `
for (const top of [1]) load(top);
function load(s) { return top[s](s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name bound by a for await header, indexed after the loop", map[string]string{"app.js": `
async function load(s, xs) {
  for await (const parent of xs) {}
  return parent[s](s);
}
load(process.argv, []);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a TypeScript declare const", map[string]string{"app.ts": `
declare const window: any;
const e = window.eval;
function load(s: string) { return e(s); }
load(process.argv[2]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a TypeScript declare const, indexed", map[string]string{"app.ts": `
declare const window: any;
function load(k: string, s: string) { return window[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a TypeScript declare function", map[string]string{"app.ts": `
declare function self(): void;
function load(k: string, s: string) { return self[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a TypeScript declare global block", map[string]string{"app.ts": `
declare global { var self: any; }
function load(k: string, s: string) { return self[k](s); }
load(process.argv[2], process.argv[3]);
export {};
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a TypeScript declare module block", map[string]string{"app.ts": `
declare module 'x' { const top: any; }
function load(k: string, s: string) { return top[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a TypeScript namespace var, read outside it", map[string]string{"app.ts": `
namespace N { var self = 1; }
function load(k: string, s: string) { return self[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in an import type", map[string]string{"app.ts": `
import type { self } from './t';
const e = self.eval;
function load(s: string) { return e(s); }
load(process.argv[2]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in an inline import type", map[string]string{"app.ts": `
import { type self, load } from './t';
function run(k: string, s: string) { return self[k](s); }
run(process.argv[2], load(process.argv[3]));
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a default import type", map[string]string{"app.ts": `
import type top from './t';
function load(k: string, s: string) { return top[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name as an arrow parameter in a ternary branch", map[string]string{"app.js": `
const c = process.env.X;
var e = c ? window => 1 : window.eval;
function load(s) { return e(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name as an arrow parameter in a nested ternary branch", map[string]string{"app.js": `
const c = process.env.X;
var e = c ? window => (c ? 1 : 2) : c ? 0 : window.eval;
function load(s) { return e(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global in a ternary else branch handed on", map[string]string{"app.js": `
function run(g, k, s) { return g[k](s); }
function load(s) { return run(process.env.X ? null : globalThis, 'eval', s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global in a ternary else branch returned", map[string]string{"app.js": `
function pick(c) { return c ? undefined : globalThis; }
function load(k, s) { return pick(0)[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global thrown", map[string]string{"app.js": `
function load(k, s) { try { throw globalThis; } catch (g) { return g[k](s); } }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global stored in a member", map[string]string{"app.js": `
const o = {};
o.g = globalThis;
function load(k, s) { return o.g[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global stored in a computed member", map[string]string{"app.js": `
const o = {};
o['g'] = window;
function load(k, s) { return o.g[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function return this stored in a member", map[string]string{"app.js": `
const o = {};
o.g = Function('return this')();
function load(k, s) { return o.g[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a TypeScript declare global function", map[string]string{"app.ts": `
declare global { function self(): any; }
function load(k: string, s: string) { return self[k](s); }
load(process.argv[2], process.argv[3]);
export {};
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a TypeScript declare namespace function", map[string]string{"app.ts": `
declare namespace A { function self(): any; }
function load(k: string, s: string) { return self[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a dotted TypeScript declare namespace function", map[string]string{"app.ts": `
declare namespace A.B { function self(): any; }
function load(k: string, s: string) { return self[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name imported inside a TypeScript declare module", map[string]string{"app.ts": `
declare module 'x' { import self from 'y'; }
function load(k: string, s: string) { return self[k](s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global destructured by assignment with a computed key", map[string]string{"app.js": `
let f;
function load(k, s) { ({ [k]: f } = globalThis); return f(s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonEvaluatedCode},
		{"global destructured into a parameter default", map[string]string{"app.js": `
function run(e, s) { return e(s); }
function load(s, { eval: e } = globalThis) { return run(e, s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"require after a member named function", map[string]string{"app.js": `
const x = {};
x.function
foo(require);
function foo(r) { return r(process.argv[2]); }
`}, plugin.PartialReasonComputedRequireSpecifier},
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

// TestCallGraph_LoaderShapesThatHandNothingOn is the control for the shapes above: a
// parameter or function named require, a test of a loader, and Function.prototype's
// call/apply/bind reached as a chain or a value load nothing this lane does not read.
func TestCallGraph_LoaderShapesThatHandNothingOn(t *testing.T) {
	cases := []struct{ name, app string }{
		{"browserify module wrapper", "var mods = {1: [function (require, module, exports) { module.exports = require('./util'); }, {}]};"},
		{"this indexed in generator methods", "class C { *items(k) { yield this[k](); } }\nconst o = { *gen(k) { yield this[k](); } };\nmodule.exports = { C, o };"},
		{"global alias in parentheses read by name", "const g = (globalThis);\nmodule.exports = g.TextEncoder;"},
		{"generator wrapper", "var mods = [function* (exports, require) { yield require('./util'); }];"},
		{"arrow parameters", "const wrap = (require, module) => require('./util');"},
		{"lone arrow parameter", "const wrap = require => require('./util');"},
		{"function named require", "function require(name) { return name; }"},
		{"module.require tested before a literal call", "const freeModule = typeof module == 'object' && module;\nconst types = freeModule && freeModule.require && freeModule.require('./util');"},
		{"require.main compared", "if (require.main === module) { load(process.argv); }"},
		{"require negated", "if (!require) { load(process.argv); }"},
		{"require compared on the right", "if (undefined !== require) { load(process.argv); }"},
		{"require as a ternary test", "const t = require ? 1 : 0;"},
		{"Function.call bound", "const has = Function.call.bind(Object.prototype.hasOwnProperty);"},
		{"Function.bind applied", "function make(Parent, args) { return new (Function.bind.apply(Parent, args))(); }"},
		{"Function.call applied", "function push() { return Function.call.apply(Array.prototype.push, arguments); }"},
		{"Function.bind as a polyfill fallback", "const bind = Function.bind || function bind(that) { return that; };"},
		{"Function.call handed on", "function ctx(fn, that) { return fn; }\nconst c = ctx(Function.call, load);"},
		{"Function compared", "function isCtor(f) { return f instanceof Function || (Function === f); }"},
		{"global member read", "const enc = globalThis.TextEncoder;"},
		{"imported names of global names", "import { top, left } from './util';\nimport * as parent from './util';\nimport self from './util';\nexport const placements = [top, left, parent, self];"},
		{"global name as an arrow parameter", "const isSuper = (node, parent) => isClass(parent) && parent.superClass === node;\nfunction isClass(n) { return !!n; }"},
		{"global name as a parameter of a multi-line arrow", "const isMember = (node, parent) =>\n  isA(parent) ||\n  isB(parent);\nfunction isA(n) { return !!n; }\nfunction isB(n) { return !n; }"},
		{"global name as an index key", "function pad(col) { return col.padding[top] || 0; }"},
		{"parent as a local", "function walk(node, k) { const parent = node.parent; return parent[k]; }"},
		{"top as a parameter", "function peek(top, k) { return top[k](); }"},
		{"frames member read", "const n = frames.length;"},
		{"window destructured from a local", "function close(state, w) { const { window } = state; w.closeWindow(window); }"},
		{"top-level var of a global name replaced", "var global = make();\nif (global.RegExp) { redefine(global, 'RegExp', {}); }\nfunction make() { return {}; }\nfunction redefine(o, k, v) { o[k] = v; }"},
		{"UMD wrapper assigning the global", "(function (global, factory) { typeof exports === 'object' ? factory(exports) : (global = global || self, factory(global.Lib = {})); }(this, function (exports) { exports.x = 1; }));"},
		{"interface method returning this", "interface Emitter { on(name: string, fn: Handler): this; off: (name: string) => this; }"},
		{"computed method returning this", "class S { [Symbol.iterator]() { return this; } }"},
		{"generic method handing on this", "class S { lift<R>(op: R): S { const s = new S(this, this); return s; } }"},
		{"UMD wrapper", "(function (root, factory) { if (typeof define === 'function') define(factory); else root.Lib = factory(); }(this, function () { return {}; }));"},
		{"UMD wrapper through call", "(function (root) { root.Lib = {}; }).call(this, this);"},
		{"IIFE called with this", "(function () { var x = 1; return x; }).call(this);"},
		{"global root from Function", "var root = Function('return this')() || {};"},
		{"Function of parameters", "const add = new Function('a', 'b', 'return a + b');"},
		{"Function of a parameter list", "const min = Function('a, b', 'return a < b ? a : b');"},
		{"Function with an empty body", "const noop = Function('');"},
		{"Function of nothing", "const nil = Function();"},
		{"Function body with a string", "const tag = Function('a', 'return a == \"x\" ? 1 : 0');"},
		{"global require tested", "const electron = typeof window !== 'undefined' && !!(window.require && window.process);"},
		{"global from Function read by a literal member", "const T = Function('return this')().TextEncoder;"},
		{"global alias guarded by tests", "var freeGlobal = typeof global == 'object' && global && global.Object === Object && global;\nvar root = freeGlobal || {};"},
		{"top-level this tested", "var __extends = (this && this.__extends) || function (d, b) { d.prototype = b; };"},
		{"TypeScript function return type", "function pick(this: Box, k: string): Box { const s = wrap(this); return s; }\nfunction wrap(o) { return o; }"},
		{"self declared from this", "function Stream(k, fn) { var self = this; fn.call(self, k); return self[k](); }"},
		{"self as a parameter", "function bind(self, fn) { return fn.apply(self, arguments); }"},
		{"self as an arrow parameter", "const call = (self, k) => { return self[k](); };"},
		{"global as a block-scoped local", "function walk(node) { let global = node.scope; return global[node.name](); }"},
		{"window declared from a parameter", "function setup(win) { const window = win; return window[win.key](); }"},
		{"self declared in a nested function", "function outer(o) { return function inner() { var self = o; return self[o.k](); }; }"},
		{"this handed on in a plain function", "function wrap(fn) { return function () { return fn.apply(this, arguments); }; }"},
		{"this aliased in a plain function", "function Box(k) { var that = this; that[k] = 1; return that; }"},
		{"this indexed without a call in a plain function", "function Box(k) { this[k] = 1; }"},
		{"global literal key", "const enc = globalThis['TextEncoder'];"},
		{"global probed", "const hasWin = typeof window !== 'undefined' && window === self;"},
		{"this indexed in a method", "const o = { pick(k) { return this[k](); } };"},
		{"this indexed in a class method", "class Box { pick(k) { return this[k](); } }"},
		{"this indexed in an arrow inside a method", "class Box { pick(k) { const f = () => this[k](); return f(); } }"},
		{"this indexed in a getter", "const o = { get v() { return this['_' + 'v']; } };"},
		{"this indexed in a constructor", "class Box { constructor(k) { this[k](1); } }"},
		{"global name bound by a for-of header, indexed in the body", "for (const self of [load]) { self[process.argv[2]](1); }\nfunction load(s) { return s; }"},
		{"global name bound by a for header, indexed in the body", "for (let top = {}; top; top = null) { top[process.argv[2]](1); }"},
		{"global name bound by a for await header, indexed in the body", "async function run(xs) { for await (const parent of xs) { parent[process.argv[2]](1); } }"},
		{"a value import beside an inline type import", "import self, { type T } from './util';\nself[process.argv[2]](1);"},
		{"an import named type", "import type from './util';\nimport { type as t } from './util';\ntype[process.argv[2]](t);"},
		{"global name declared by a TypeScript namespace var, indexed inside it", "namespace N { var self = { a: 1 }; self[process.argv[2]](1); }"},
		{"global name as an arrow parameter in a ternary branch", "const f = process.env.X ? window => window[process.argv[2]](1) : null;"},
		{"an arrow body holding a whole ternary", "const f = window => window ? window[process.argv[2]](1) : 0;"},
		{"Function as an optional parameter type", "function run(cb?: Function, f?: Function): Function | undefined { return cb; }"},
		{"global name as an arrow parameter used in its own ternary else", "const c = process.env.X;\nconst f = window => c ? 0 : window[process.argv[2]](1);"},
		{"Function as a parameter type after a ternary default", "function run(a = process.env.X ? 1 : 2, cb: Function) { return cb; }"},
		{"Function as a type after a nullish default", "const v = process.env.X ?? 'y'\nlet cb: Function;"},
		{"the global assigned to an undeclared global name", "let x = 1;\nself = globalThis;\nconsole.log(self.location, x);"},
		{"members compared with globals and a compound assignment", "const o = {};\nif (o.g === globalThis || o.h !== window || o.i >= self || o.j <= top) {}\nlet n = 0;\nn += self;"},
		{"a member compared with a global", "const o = {};\nif (o.g == globalThis) { o.g = 1; }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeProgram(t, map[string]string{
				"util.js": "function trim(s) { return s.trim(); }\nmodule.exports = { trim };\n",
				"app.js":  "const { trim } = require('./util');\n" + tc.app + "\nfunction load(s) { return trim(s); }\nload(process.argv);\n",
			})
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if len(res.Edges) == 0 {
				t.Fatalf("control must have edges; got none")
			}
			if hasDidNotRun(res.Partiality) {
				t.Errorf("declared %v; want inherent reasons only", res.Partiality.Reasons)
			}
		})
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
