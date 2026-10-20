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
