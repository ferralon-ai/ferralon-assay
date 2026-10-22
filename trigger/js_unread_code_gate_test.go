package trigger

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
		{"module indexed by a computed key", `
const j = module['re' + 'quire']('json5');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"module indexed by an optional computed key", `
const j = module?.[process.argv[3]]('json5');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function read from a parenthesised global", `
const F = (globalThis).Function;
const j = F('return require("json5")')();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"typeof before an optional require call", `
let j = {};
if (typeof require?.('json5') === 'object') j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"typeof before require.call", `
let j = {};
if (typeof require.call(null, 'json5') === 'object') j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"typeof before require.apply", `
let j = {};
if (typeof require.apply(null, ['json5']) === 'object') j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"imports entry with a development branch that is a package", `
const j = require('#j');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json": `{"name":"fixture","imports":{"#j":{"development":"json5","default":"./plugins/index.js"}},"dependencies":{"json5":"2.2.1"}}`,
		}},
		{"imports entry with a browser branch absent from the tree", `
const j = require('#j');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json": `{"name":"fixture","imports":{"#j":{"browser":"./missing.js","default":"./plugins/index.js"}},"dependencies":{"json5":"2.2.1"}}`,
		}},
		{"module aliased then indexed", `
const m = module;
const j = m[process.argv[3]]('json5');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"module passed as a value", `
const j = Reflect.get(module, 'require')('json5');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"module._compile", `
const j = {};
module._compile('module.exports = require("json5")', 'x.js');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"eval read from a parenthesised global", `
const e = (globalThis).eval;
const j = e('require')('json5');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"createRequire result optionally called under typeof", `
const r = module.constructor.createRequire(__filename);
let j = {};
if (typeof r?.('json5') === 'object') j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"createRequire result called through .call under typeof", `
const r = module.constructor.createRequire(__filename);
let j = {};
if (typeof r.call(null, 'json5') === 'object') j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"process.dlopen destructured", `
const j = { exports: {} };
const { dlopen } = process;
dlopen(j, './x.node');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"process.dlopen by a computed key", `
const j = { exports: {} };
process['dl' + 'open'](j, './x.node');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"process aliased then indexed", `
const j = { exports: {} };
const p = process;
p[process.argv[3]](j, './x.node');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"process passed as a value", `
const j = { exports: {} };
Reflect.get(process, process.argv[3])(j, './x.node');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"process reached through the global and indexed", `
const j = { exports: {} };
global.process[process.argv[3]](j, './x.node');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Module._load by a computed key on an alias", `
const M = module.constructor;
const j = M['_lo' + 'ad']('json5', module);
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Module._load destructured", `
const { _load } = module.constructor;
const j = _load('json5', module);
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function reached through constructor.constructor", `
const j = [].constructor.constructor('return require("json5")')();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function reached through literal constructor keys", `
const j = ({})['constructor']['constructor']('return require("json5")')();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"AsyncFunction through Object.getPrototypeOf", `
const AF = Object.getPrototypeOf(async function () {}).constructor;
const j = { parse: String };
AF('return require("json5")')();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"GeneratorFunction through Reflect.getPrototypeOf and optional chaining", `
const GF = Reflect.getPrototypeOf(function* () {})?.constructor;
const j = { parse: String };
GF('yield require("json5")')().next();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"AsyncFunction through __proto__", `
const AF = (async () => {}).__proto__.constructor;
const j = { parse: String };
AF('return require("json5")')();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function as the constructor of a function expression", `
const F = (function () {}).constructor;
const j = F('return require("json5")')();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"imports entry whose worker branch is another in-tree module", `
const j = require('#j');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json": `{"name":"fixture","imports":{"#j":{"worker":"./plugins/index.js","default":"./other.js"}},"dependencies":{"json5":"2.2.1"}}`,
			"other.js":     "function parse(s) { return s; }\nmodule.exports = { parse };\n",
		}},
		{"workspace member whose require branch is another in-tree module", `
const j = require('m');
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, map[string]string{
			"package.json":            `{"name":"fixture","workspaces":["packages/*"],"dependencies":{"json5":"2.2.1"}}`,
			"packages/m/package.json": `{"name":"m","exports":{".":{"import":"./esm.js","require":"./cjs.js"}}}`,
			"packages/m/esm.js":       "export function parse(s) { return s; }\n",
			"packages/m/cjs.js":       "function parse(s) { return s; }\nmodule.exports = { parse };\n",
		}},
		{"Function called as a named function's constructor", `
const j = { parse: String };
function g() {}
g.constructor(process.argv[3])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function aliased from a named function's constructor", `
const j = { parse: String };
function g() {}
const F = g.constructor;
F(process.argv[3])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function as the constructor of a member function", `
const j = { parse: String };
[].map.constructor(process.argv[3])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function as a constructor reached by a literal key and called", `
const j = { parse: String };
function g() {}
g['constructor'](process.argv[3])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function as a constructor called through .call", `
const j = { parse: String };
function g() {}
g.constructor.call(null, process.argv[3])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function as an optionally read constructor, called", `
const j = { parse: String };
function g() {}
g?.constructor(process.argv[3])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function as a constructor passed as a value", `
const j = { parse: String };
function g() {}
Reflect.construct(g.constructor, [process.argv[3]])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function as a constructor constructed off a non-this receiver", `
const j = { parse: String };
function g() {}
new g.constructor(process.argv[3])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function reached by two computed keys and called", `
const j = { parse: String };
const k = process.argv[4];
({})[k][k](process.argv[3])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function reached by two optional computed keys and called", `
const j = { parse: String };
const k = process.argv[4];
({})?.[k]?.[k](process.argv[3])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function reached by two computed keys and aliased", `
const j = { parse: String };
const k = process.argv[4];
const F = ({})[k][k];
F(process.argv[3])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function reached by a computed key after a constructor member", `
const j = { parse: String };
const k = process.argv[4];
({}).constructor[k](process.argv[3])();
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"exported createRequire result", `
export const r = module.constructor.createRequire(__filename);
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"exported createRequire result declared with let", `
export let r = module.constructor.createRequire(__filename);
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"eval aliased off a named receiver", `
const frame = { contentWindow: globalThis };
const e = frame.contentWindow.eval;
e(process.argv[3]);
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"eval returned off a parameter", `
function evalOf(w) { return w.eval; }
module.exports = evalOf;
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function aliased off a named receiver", `
const frame = { contentWindow: globalThis };
const F = frame.contentWindow.Function;
F(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"webpack's runtime require called with a computed specifier", `
const j = __non_webpack_require__(process.argv[3]);
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"webpack's runtime require aliased", `
const r = __non_webpack_require__;
const j = r(process.argv[3]);
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"the module wrapper's require read through top-level arguments", `
const r = arguments[1];
const j = r(process.argv[3]);
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"the module wrapper's require read through arguments in a top-level arrow", `
const pick = () => arguments[1];
const j = pick()(process.argv[3]);
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"module exported as a value under another name", `
export { module as m };
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"require exported as a value", `
export { require };
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"process exported as a value under another name", `
export { process as p };
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function destructured as a renamed constructor key", `
const g = function () {};
const { constructor: F } = g;
F(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function destructured as a shorthand constructor key", `
const g = function () {};
const { constructor } = g;
constructor(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function destructured in a parameter", `
function h({ constructor: F }) { return F(process.argv[3])(); }
h(function () {});
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function destructured as a quoted constructor key", `
const { 'constructor': F } = function () {};
F(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function destructured as a computed constructor key", `
const { ['constructor']: F } = function () {};
F(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function destructured through a nested constructor pattern", `
const { constructor: { constructor: F } } = {};
F(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function read through Reflect.get", `
const g = function () {};
Reflect.get(g, 'constructor')(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function read through Object.getOwnPropertyDescriptor", `
const g = function () {};
Object.getOwnPropertyDescriptor(Object.getPrototypeOf(g), 'constructor').value(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function read through Reflect get as a computed member", `
const g = function () {};
Reflect['get'](g, 'constructor')(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function read through a destructured Reflect.get", `
const g = function () {};
const { get } = Reflect;
get(g, 'constructor')(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function read through Object.getOwnPropertyDescriptors", `
const g = function () {};
Object.getOwnPropertyDescriptors(Object.getPrototypeOf(g)).constructor.value(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"the module wrapper's require read through arguments in a class's computed key", `
class A { [arguments[1](process.argv[3]).k]() {} }
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"the module object read before a top-level var of its name is assigned", `
steal();
function steal() { return take(module); }
function take(m) { return m.require(process.argv[3]); }
var module = { exports: {} };
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructed as this.constructor in a static method", `
class A { static make(s) { return new this.constructor(s); } }
A.make(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructed as this.constructor in a function called on a function", `
function m(s) { return new this.constructor(s); }
m.call(function () {}, process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructed as this.constructor in a class method called on a function", `
class A { m(s) { return new this.constructor(s); } }
A.prototype.m.call(function () {}, process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructed as this.constructor in a prototype method called on a function", `
function Foo() {}
Foo.prototype.m = function (s) { return new this.constructor(s); };
Foo.prototype.m.call(function () {}, process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructed as this.constructor in a class method copied onto a function", `
class A { m(s) { return new this.constructor(s); } }
const f = function () {};
f.m = A.prototype.m;
f.m(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructed as this.constructor in a class method applied through Reflect.apply", `
class A { m(s) { return new this.constructor(s); } }
Reflect.apply(A.prototype.m, function () {}, [process.argv[3]])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructed as this.constructor in a method added to Object.prototype", `
Object.prototype.mk = function (s) { return new this.constructor(s); };
(function () {}).mk(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructed as this.constructor with a tagged template in a class method called on a function", `
class A { m(s) { return new this.constructor ` + "`a${s}`" + `; } }
A.prototype.m.call(function () {}, process.argv[3]);
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"this.constructor constructed with arguments in an instance method and a prototype method", `
class Box { constructor(v) { this.v = v; } clone() { return new this.constructor(this.v); } }
new Box(1).clone();
function Foo(v) { this.v = v; }
Foo.prototype.clone = function () { return new this.constructor(this.v); };
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"require optionally called on the right of a comparison", `
let j = { parse: String };
if (j === require?.(process.argv[3])) j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"require optionally called under a negation", `
let j = { parse: String };
if (!require?.(process.argv[3])) j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function returned by valueOf on a function's constructor", `
const f = function () {};
f.constructor.valueOf()(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function returned by valueOf on a function's constructor read optionally", `
const f = function () {};
f.constructor?.valueOf()(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructor as the left operand of ??", `
const a = function () {};
const r = (a.constructor ?? 0)(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"constructor of a function expression read for a member", `
const n = (function () {}).constructor.name;
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"get of a constructor property descriptor", `
const P = Object.getPrototypeOf(function () {});
const g = Object.getOwnPropertyDescriptors(P).constructor.get;
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructor called on the right of instanceof", `
const a = function () {};
const t = 0 instanceof a.constructor(process.argv[3]);
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructor called through .apply", `
const a = function () {};
a.constructor.apply(null, [process.argv[3]])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructor bound through .bind", `
const a = function () {};
a.constructor.bind(null)(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function constructor called in an if condition", `
const a = function () {};
if (a.constructor(process.argv[3])()) a.n = 1;
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function read by an optional literal key", `
function f(o) { const F = o?.['Function']; return F(process.argv[3])(); }
f({});
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function destructured as a shorthand constructor key before another key", `
const { constructor, name } = function () {};
constructor(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function destructured as a constructor key with a default", `
const { constructor = null } = function () {};
constructor(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function destructured as a constructor key in an assignment", `
let F;
({ constructor: F } = function () {});
F(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"constructor key destructured in a for-in head", `
let F;
for ({ constructor: F } in { a: 1 }) F(process.argv[3]);
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function destructured as a constructor key in a for-of head", `
let F;
for ({ constructor: F } of [function () {}]) F(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"constructor key passed as the only argument", `
function prop(k) { return (o) => o[k]; }
const get = prop('constructor');
get(function () {})(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"constructor key passed as a middle argument", `
function pluck(o, k, d) { return o[k] || d; }
const F = pluck(function () {}, 'constructor', null);
F(process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"a local module initialised from a parameter and passed on", `
function helper(m) { return m.require(process.argv[3]); }
function f(a) { var module = a; return helper(module); }
f({});
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"a local module initialised from a name in a declaration list and passed on", `
function helper(m) { return m.require(process.argv[3]); }
function f() { var module = globalThis.m, b = {}; return helper(module); }
f();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"require called as a member of this", `
function f() { return this.require(process.argv[3]); }
f();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function reached by two template-literal keys", `
const o = function () {};
const n = 'constructor';
o[` + "`${n}`" + `][` + "`${n}`" + `](process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"Function reached by two computed keys and called through .call", `
const o = function () {};
const k = 'constructor';
o[k][k].call(null, process.argv[3])();
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"a local module destructured from an object literal and passed on", `
function helper(m) { return m.require(process.argv[3]); }
function f(x) { const { m: module } = { m: x }; return helper(module); }
f({});
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"a local module object literal rebound by a for-of head and passed on", `
function helper(m) { return m.require(process.argv[3]); }
function f(xs) { var module = {}; for (module of xs) helper(module); }
f([{}]);
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"a local module object literal rebound by a for-in head and passed on", `
function helper(m) { return m.require(process.argv[3]); }
function f(o) { var module = {}; for (module in o) helper(module); }
f({ a: 1 });
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"a local module object literal rebound in an array pattern of a for-in head and passed on", `
function helper(m) { return m.require(process.argv[3]); }
function f(o) { var module = {}; for ([module] in o) helper(module); }
f({ a: 1 });
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"a local module initialised by a logical-or assignment and passed on", `
function helper(m) { return m.require(process.argv[3]); }
function f(a) { var module = a ||= {}; return helper(module); }
f({});
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"a local module initialised by a nullish assignment and passed on", `
function helper(m) { return m.require(process.argv[3]); }
function f(a) { var module = a ??= {}; return helper(module); }
f({});
const j = { parse: String };
function load(s) { return j.parse(s); }
load(process.argv[2]);
`, nil},
		{"a local module initialised by an object literal and && and passed on", `
function helper(m) { return m.require(process.argv[3]); }
function f(a) { var module = {} && a; return helper(module); }
f({});
const j = { parse: String };
function load(s) { return j.parse(s); }
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

// TestUndeterminedReason_JSRecognizedLoadsCanRefute: loads and loader mentions the lane
// recognizes in full hand nothing on that it does not read, so a program made only of them
// keeps its call edges and passes the gate. The rows above are held by the use they add, not
// by an inversion that declares every program.
func TestUndeterminedReason_JSRecognizedLoadsCanRefute(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		files map[string]string
	}{
		{"plain require of an in-tree module", "const j = require('./plugins');", nil},
		{"static import of an in-tree module", "import { parse } from './plugins/index.js';\nconst j = { parse };", nil},
		{"require property of a plain object", "const opts = { a: 1 };\nconst r = opts.require;\nconst j = require('./plugins');", nil},
		{"require as an object key", "const cfg = { require: ['./plugins'] };\nconst j = require('./plugins');", nil},
		{"require.main tested against module", "const j = require('./plugins');\nif (require.main === module) load('x');", nil},
		{"module and process data members", "const j = require('./plugins');\nmodule.exports = { id: module.id };\nconst { env } = process;\nif (module.hot) module.hot.accept();", nil},
		{"constructor of a value and of this read, tested and assigned", "class Box { constructor(v) { this.v = v; } }\nconst b = new Box(1);\nfunction Sub() {}\nSub.prototype.constructor = Sub;\nconst same = b.constructor === Box && b instanceof b.constructor && b.constructor.name !== '' && Object.getPrototypeOf(b).constructor !== Object;\nconst j = require('./plugins');", nil},
		{"a function's constructor name used as a string", "const f = function () {};\nconst label = 'type: ' + f.constructor.name;\nconst j = require('./plugins');", nil},
		{"eval and Function members tested", "const opts = {};\nconst j = require('./plugins');\nif (opts.eval) load('x');\nconst on = !opts.Function && opts.eval !== true;", nil},
		{"webpack's runtime require of an in-tree module", "const j = __non_webpack_require__('./plugins');", nil},
		{"escaped specifier of an in-tree module", "const j = require('./\\x70lugins');", nil},
		{"arguments inside a function, as a member and as a key", "function first() { return arguments[0]; }\nconst info = { arguments: first.arguments };\nconst j = require('./plugins');", nil},
		{"local values exported under the names module, require and process", "const own = {};\nexport { own as module, own as require, own as process };\nconst j = require('./plugins');", nil},
		{"constructor as a class method and an object-literal key", "class Box { constructor(v) { this.v = v; } }\nfunction inherit(sub, sup) { sub.prototype = Object.create(sup && sup.prototype, { constructor: { value: sub, writable: true } }); }\nconst desc = { constructor: Box, f({ a }) { return a; } };\nconst j = require('./plugins');", nil},
		{"constructor as a quoted and a computed object-literal key", "class Box {}\nconst a = { 'constructor': Box };\nconst b = { ['constructor']: Box, \"constructor\": Box };\nconst j = require('./plugins');", nil},
		{"a prototype-pollution guard on a constructor key", "function set(o, k, v) { if (k === '__proto__' || k === 'constructor') return; o[k] = v; }\nconst name = Reflect.get(set, 'name');\nconst j = require('./plugins');", nil},
		{"arguments inside class methods", "class A { m() { return arguments[0]; } static s() { return arguments.length; } constructor() { this.n = arguments.length; } }\nconst j = require('./plugins');", nil},
		{"this.constructor constructed with no arguments", "class Box { clone() { return new this.constructor(); } }\nfunction Foo() {}\nFoo.prototype.clone = function () { return new this.constructor; };\nclass Reg { static make() { return new this.constructor(); } }\nconst j = require('./plugins');", nil},
		{"the webpack 5 runtime handing its module record to a module factory", "var __webpack_modules__ = {};\nvar __webpack_module_cache__ = {};\nfunction __webpack_require__(moduleId) {\n  var cachedModule = __webpack_module_cache__[moduleId];\n  if (cachedModule !== undefined) return cachedModule.exports;\n  var module = __webpack_module_cache__[moduleId] = { exports: {} };\n  __webpack_modules__[moduleId](module, module.exports, __webpack_require__);\n  return module.exports;\n}\nconst j = require('./plugins');", nil},
		{"eval and Function members assigned", "const opts = {};\nopts.eval = false;\nopts.Function = null;\nconst j = require('./plugins');", nil},
		{"a two-dimensional array read, written and compared", "const grid = [[0]];\nlet n = 0;\nfor (let i = 0; i < 1; i++) { grid[i][0] = grid[i][n] + 1; n += grid[n][i]; if (grid[i][n] === 0) n--; }\nconst j = require('./plugins');", nil},
		{"imports entry whose condition branches are one module", "const j = require('#j');", map[string]string{
			"package.json": `{"name":"fixture","imports":{"#j":{"worker":"./plugins/index.js","default":"./plugins/index.js"}},"dependencies":{"json5":"2.2.1"}}`,
		}},
		{"imports entry whose types branch is a declaration file", "const j = require('#j');", map[string]string{
			"package.json": `{"name":"fixture","imports":{"#j":{"types":"./plugins/index.d.ts","default":"./plugins/index.js"}},"dependencies":{"json5":"2.2.1"}}`,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.src + "\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"
			store, edges := gateStoreFromJS(t, src, tc.files)
			if edges == 0 {
				t.Fatalf("program must have call edges")
			}
			if reason, ok := undeterminedReason(store, "a1", json5Package); ok {
				t.Errorf("undeterminedReason = (%q, true); want refutable", reason)
			}
		})
	}
}

// escapedKeyShapes are the forms that hand a member named by a string key on as a value: a
// destructuring pattern, Reflect.get, a property descriptor and a bracket call. KEY stands
// for the key literal.
var escapedKeyShapes = []struct{ name, src string }{
	{"destructured", "const { KEY: F } = function () {};\nF(process.argv[3])();\n"},
	{"read through Reflect.get", "const g = function () {};\nReflect.get(g, KEY)(process.argv[3])();\n"},
	{"read through Object.getOwnPropertyDescriptor", "const g = function () {};\nObject.getOwnPropertyDescriptor(Object.getPrototypeOf(g), KEY).value(process.argv[3])();\n"},
	{"called by a bracket key", "const g = function () {};\ng[KEY](process.argv[3])();\n"},
}

// TestUndeterminedReason_JSEscapedConstructorKeyNeverRefutes: a constructor key reads as its
// value however it is spelled, so each escape spelling in each shape that reaches Function
// through it holds the verdict, as the plain key does.
func TestUndeterminedReason_JSEscapedConstructorKeyNeverRefutes(t *testing.T) {
	spellings := []struct{ name, key string }{
		{"hex escape", `'\x63onstructor'`},
		{"unicode escape", `'\u0063onstructor'`},
		{"code point escape", `'\u{0063}onstructor'`},
		{"surrogate-free code point escape", `'\u{63}onstructor'`},
		{"line continuation", "'constr\\\nuctor'"},
		{"CRLF line continuation", "'constr\\\r\nuctor'"},
		{"legacy octal escape", `'\143onstructor'`},
		{"mixed escapes", "'\\x63o\\u006E\\u{73}t\\\nr\\165ctor'"},
		{"double-quoted hex escape", `"\x63onstructor"`},
		{"escaped template", "`\\x63onstructor`"},
	}
	for _, sp := range spellings {
		for _, sh := range escapedKeyShapes {
			t.Run(sp.name+" "+sh.name, func(t *testing.T) {
				src := strings.ReplaceAll(sh.src, "KEY", sp.key) + "const j = { parse: String };\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"
				store, edges := gateStoreFromJS(t, src, nil)
				if edges == 0 {
					t.Fatalf("program must have call edges")
				}
				if reason, ok := undeterminedReason(store, "a1", json5Package); !ok || reason != report.ReasonAnalysisDidNotRun {
					t.Errorf("undeterminedReason = (%q, %v); want (%q, true): not_exploitable would stand", reason, ok, report.ReasonAnalysisDidNotRun)
				}
			})
		}
	}
}

// TestUndeterminedReason_JSEscapedLoaderSpellingNeverRefutes: the other forms that name a
// loader or evaluator by an escaped key, and names spelled with an identifier escape, which
// the scan cannot read, hold the verdict.
func TestUndeterminedReason_JSEscapedLoaderSpellingNeverRefutes(t *testing.T) {
	cases := []struct{ name, src string }{
		{"constructor as an escaped computed destructuring key", "const { ['\\x63onstructor']: F } = function () {};\nF(process.argv[3])();\n"},
		{"constructor as an escaped optional bracket key", "const g = function () {};\ng?.['\\x63onstructor'](process.argv[3])();\n"},
		{"constructor as an escaped argument of a destructured Reflect.get", "const g = function () {};\nconst { get } = Reflect;\nget(g, '\\x63onstructor')(process.argv[3])();\n"},
		{"Function as an escaped key of the global", "globalThis['\\x46unction'](process.argv[3])();\n"},
		{"eval as an escaped key of the global", "globalThis['\\u0065val'](process.argv[3]);\n"},
		{"dlopen as an escaped key of process", "const m = { exports: {} };\nprocess['\\x64lopen'](m, './x.node');\n"},
		{"constructor of an escaped constructor key after a comma, read for its name", "const g = function () {};\nconst label = g[0, '\\x63onstructor'].constructor.name;\n"},
		{"malformed escaped key of the module object", "const j = module['\\x6']('json5');\n"},
		{"constructor member spelled with an identifier escape", "const g = function () {};\ng.\\u0063onstructor(process.argv[3])();\n"},
		{"constructor destructured under an identifier escape", "const { \\u{63}onstructor: F } = function () {};\nF(process.argv[3])();\n"},
		{"Function spelled with an identifier escape", "\\u0046unction(process.argv[3])();\n"},
		{"eval spelled with an identifier escape", "\\u0065val(process.argv[3]);\n"},
		{"require spelled with an identifier escape", "\\u0072equire(process.argv[3]);\n"},
		{"module spelled with an identifier escape", "\\u006dodule.require(process.argv[3]);\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.src + "const j = { parse: String };\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"
			store, edges := gateStoreFromJS(t, src, nil)
			if edges == 0 {
				t.Fatalf("program must have call edges")
			}
			if reason, ok := undeterminedReason(store, "a1", json5Package); !ok || reason != report.ReasonAnalysisDidNotRun {
				t.Errorf("undeterminedReason = (%q, %v); want (%q, true): not_exploitable would stand", reason, ok, report.ReasonAnalysisDidNotRun)
			}
		})
	}
}

// TestUndeterminedReason_JSEscapedLookalikeKeyCanRefute is the control: an escaped key whose
// value is not constructor reads as that value, in each shape, so it does not hold the
// verdict.
func TestUndeterminedReason_JSEscapedLookalikeKeyCanRefute(t *testing.T) {
	spellings := []struct{ name, key string }{
		{"truncated", `'\x63onstructo'`},
		{"capital C", `'\x43onstructor'`},
		{"trailing NUL", `'constructor\x00'`},
		{"harmless member", `'\x6eame'`},
	}
	for _, sp := range spellings {
		for _, sh := range escapedKeyShapes {
			t.Run(sp.name+" "+sh.name, func(t *testing.T) {
				src := strings.ReplaceAll(sh.src, "KEY", sp.key) + "const j = require('./plugins');\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"
				store, edges := gateStoreFromJS(t, src, nil)
				if edges == 0 {
					t.Fatalf("program must have call edges")
				}
				if reason, ok := undeterminedReason(store, "a1", json5Package); ok {
					t.Errorf("undeterminedReason = (%q, true); want refutable", reason)
				}
			})
		}
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

// TestUndeterminedReason_JSWorkspaceMemberShadow: a bare specifier naming a workspace member
// runs the member's code only when Node's node_modules walk from the importer finds the member
// itself, through a symlink to its directory, or finds nothing. A real directory or file under
// the name, nearer to the importer or at the root, or a symlink to another directory, is
// different code Node loads instead, and the verdict is held. So is a candidate that cannot be
// followed.
func TestUndeterminedReason_JSWorkspaceMemberShadow(t *testing.T) {
	const src = "const j = require('foo');\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"
	const viaSrc = "const j = require('./src/app');\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"
	installed := map[string]string{
		"package.json": `{"name":"foo","version":"9.9.9"}`,
		"index.js":     "const JSON5 = require('json5');\nmodule.exports = { parse: (s) => JSON5.parse(s) };\n",
	}
	tree := func(installedAt ...string) map[string]string {
		files := map[string]string{
			"package.json":              `{"name":"fixture","workspaces":["packages/*"],"dependencies":{"json5":"2.2.1"}}`,
			"packages/foo/package.json": `{"name":"foo","version":"1.0.0"}`,
			"packages/foo/index.js":     "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"src/app.js":                "module.exports = require('foo');\n",
		}
		for _, at := range installedAt {
			for name, body := range installed {
				files[at+"/"+name] = body
			}
		}
		return files
	}
	withFile := func(files map[string]string, name, body string) map[string]string {
		files[name] = body
		return files
	}
	member := map[string]string{"node_modules/foo": "../packages/foo"}
	const entrySrc = "const j = require('./src/entry');\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"
	// entryTo links src/entry.js to target over the member's link, with extra links added.
	entryTo := func(target string, extra map[string]string) map[string]string {
		links := map[string]string{"node_modules/foo": "../packages/foo", "src/entry.js": target}
		maps.Copy(links, extra)
		return links
	}
	withReal := func(files map[string]string) map[string]string {
		files["dist/real.js"] = "module.exports = require('foo');\n"
		return files
	}
	// outside is a directory outside the build root holding real.js beside an installed copy.
	outside := t.TempDir()
	for name, body := range map[string]string{
		"real.js":                       "module.exports = require('foo');\n",
		"node_modules/foo/package.json": installed["package.json"],
		"node_modules/foo/index.js":     installed["index.js"],
	} {
		p := filepath.Join(outside, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// req is an importer of spec; named renames the member foo to name, with its importers.
	req := func(spec string) string {
		return "const j = require('" + spec + "');\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"
	}
	named := func(name string) map[string]string {
		files := tree()
		files["packages/foo/package.json"] = `{"name":"` + name + `","version":"1.0.0"}`
		files["src/app.js"] = "module.exports = require('" + name + "');\n"
		return files
	}
	withInstalled := func(files map[string]string, at string) map[string]string {
		for name, body := range installed {
			files[at+"/"+name] = body
		}
		return files
	}
	// outsideReal drops src/app.js, whose walks would see what the row puts above the root, and
	// adds the importer's real file at ../../out from the build root.
	outsideReal := func(files map[string]string, name, body string) map[string]string {
		delete(files, "src/app.js")
		files["../../out/"+name] = body
		return files
	}
	long := strings.Repeat("f", 252) // its .json and .node candidates exceed NAME_MAX; .js does not
	stem := strings.Repeat("s", 252) // its .js file fits NAME_MAX; .mjs, .cjs, .jsx, .tsx, .vue do not
	cases := []struct {
		name  string
		src   string
		files map[string]string
		links map[string]string // symlink path to its target
		at    string            // the build root's path under the test's directory, when not the directory itself
		held  bool
	}{
		{"an installed copy at the root", src, tree("node_modules/foo"), nil, "", true},
		{"an installed copy nearer the importer than the member's link", viaSrc, tree("src/node_modules/foo"), member, "", true},
		{"a link to another directory", src, tree("vendor/foo"), map[string]string{"node_modules/foo": "../vendor/foo"}, "", true},
		{"a file Node tries before the member's link", src, withFile(tree(), "node_modules/foo.js", installed["index.js"]), member, "", true},
		{"a link that loops", src, tree(), map[string]string{"node_modules/foo": "foo"}, "", true},
		{"a symlinked importer whose real directory holds an installed copy", entrySrc,
			withReal(tree("dist/node_modules/foo")), entryTo("../dist/real.js", nil), "", true},
		{"a symlinked importer whose real file is outside the build root beside an installed copy", entrySrc,
			tree(), entryTo(filepath.Join(outside, "real.js"), nil), "", true},
		{"a .json file Node tries before the member's link", src, withFile(tree(), "node_modules/foo.json", "{}"), member, "", true},
		{"a .node file Node tries before the member's link", src, withFile(tree(), "node_modules/foo.node", ""), member, "", true},
		{"an installed copy at the root reached from a nested importer", viaSrc, tree("node_modules/foo"), nil, "", true},
		{"an installed copy above the build root", src, withInstalled(tree(), "../node_modules/foo"), nil, "repo", true},
		// Node walks the symlink's own directory under --preserve-symlinks, which the tree does not record.
		{"a symlinked importer whose own directory's ancestor holds an installed copy", req("./src/a/b/entry"),
			withReal(tree("src/a/node_modules/foo")), map[string]string{"node_modules/foo": "../packages/foo", "src/a/b/entry.js": "../../../dist/real.js"}, "", true},
		{"a symlinked importer whose real directory's ancestor holds an installed copy", entrySrc,
			withFile(tree("dist/node_modules/foo"), "dist/sub/real.js", "module.exports = require('foo');\n"), entryTo("../dist/sub/real.js", nil), "", true},
		{"a member name with a candidate that cannot be stat'ed", req(long), named(long), map[string]string{"node_modules/" + long: "../packages/foo"}, "", true},
		{"an importer with a source file name that cannot be stat'ed", req("./src/" + stem),
			withFile(tree(), "src/"+stem+".js", "module.exports = require('foo');\n"), member, "", true},
		{"a member name the walk cannot place", req("foo..bar"), named("foo..bar"), map[string]string{"node_modules/foo..bar": "../packages/foo"}, "", true},
		{"a symlinked importer whose real directory holds only the member's link", entrySrc,
			withReal(tree()), entryTo("../dist/real.js", map[string]string{"dist/node_modules/foo": "../../packages/foo"}), "", false},
		// require skips node_modules/node_modules and import checks it; whichever the importer is,
		// both find the member.
		{"the member's link at both levels a node_modules directory above the importer's real file gives", entrySrc,
			withFile(tree(), "node_modules/x/real.js", "module.exports = require('foo');\n"),
			entryTo("../node_modules/x/real.js", map[string]string{"node_modules/node_modules/foo": "../../packages/foo"}), "", false},
		{"an installed copy an import finds in a node_modules directory above the importer's real file", entrySrc,
			withFile(tree("node_modules/node_modules/foo"), "node_modules/x/real.mjs", "import j from 'foo';\nexport default j;\n"),
			map[string]string{"node_modules/foo": "../packages/foo", "src/entry.mjs": "../node_modules/x/real.mjs"}, "", true},
		{"an installed copy a require finds past the member's link in a node_modules directory above the importer's real file", entrySrc,
			withFile(tree("node_modules/foo"), "node_modules/x/real.js", "module.exports = require('foo');\n"),
			map[string]string{"node_modules/node_modules/foo": "../../packages/foo", "src/node_modules/foo": "../../packages/foo", "src/entry.js": "../node_modules/x/real.js"}, "", true},
		// The build root is node_modules/repo, and the importer's real file sits beside the member's
		// link outside it, so only the logical walk (Node's under --preserve-symlinks) passes the
		// node_modules directory above the root.
		{"an installed copy an import finds in the node_modules directory above the build root", req("./src/a/entry"),
			withInstalled(outsideReal(tree(), "real.mjs", "import j from 'foo';\nexport default j;\n"), "../node_modules/foo"),
			map[string]string{"src/a/entry.mjs": "../../../../out/real.mjs", "../../out/node_modules/foo": "../../node_modules/repo/packages/foo"}, "node_modules/repo", true},
		{"an installed copy a require finds past the member's link in the node_modules directory above the build root", req("./src/a/entry"),
			withInstalled(outsideReal(tree(), "real.js", "module.exports = require('foo');\n"), "../foo"),
			map[string]string{"src/a/entry.js": "../../../../out/real.js", "../../out/node_modules/foo": "../../node_modules/repo/packages/foo",
				"../node_modules/foo": "../repo/packages/foo"}, "node_modules/repo", true},
		{"the member's link at the root", src, tree(), member, "", false},
		{"the member's link reached from a nested importer", viaSrc, tree(), member, "", false},
		{"no installed copy", src, tree(), nil, "", false},
		{"a dangling link", src, tree(), map[string]string{"node_modules/foo": "../gone"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			if !tc.held {
				noCopyAbove(t, base, "foo")
			}
			store, edges := gateStoreFromJSAt(t, filepath.Join(base, filepath.FromSlash(tc.at)), tc.src, tc.files, tc.links)
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

// noCopyAbove fails the test when an ancestor of dir, logical or real, holds a candidate for
// package name in its node_modules, or a node_modules that cannot be searched: a walk that
// climbs past the build root would find it, and a row expecting no copy would not test that.
func noCopyAbove(t *testing.T, dir, name string) {
	t.Helper()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, start := range []string{dir, real} {
		for d := filepath.Dir(start); ; d = filepath.Dir(d) {
			for _, c := range []string{name, name + ".js", name + ".json", name + ".node"} {
				p := filepath.Join(d, "node_modules", c)
				if _, err := os.Lstat(p); err == nil || !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
					t.Fatalf("%s (%v) is above the test's build root: remove it or set TMPDIR elsewhere", p, err)
				}
			}
			if filepath.Dir(d) == d {
				break
			}
		}
	}
}

// json5Package is the package the gate assesses: the dependency every program loads or could.
var json5Package = &report.Package{Ecosystem: "npm", Name: "json5", Version: "2.2.1", PURL: "pkg:npm/json5@2.2.1"}

// gateStoreFromJS writes src as index.js over a default tree (with files added or replacing
// entries), runs the JS producer over it, and stores the call graph and reachability
// partiality, run-wide and scoped, as the reachability and exposure-footprint artifacts.
func gateStoreFromJS(t *testing.T, src string, files map[string]string) (*artifact.MemStore, int) {
	t.Helper()
	return gateStoreFromJSLinked(t, src, files, nil)
}

// gateStoreFromJSLinked is gateStoreFromJS with symlinks added to the tree, each at its path
// pointing to its target as written.
func gateStoreFromJSLinked(t *testing.T, src string, files, links map[string]string) (*artifact.MemStore, int) {
	t.Helper()
	return gateStoreFromJSAt(t, t.TempDir(), src, files, links)
}

// writeTree writes each file at its slash-separated path under dir.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// gateStoreFromJSAt is gateStoreFromJSLinked with the tree written at dir.
func gateStoreFromJSAt(t *testing.T, dir, src string, files, links map[string]string) (*artifact.MemStore, int) {
	t.Helper()
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
	for name, target := range links {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Skipf("symlink: %v", err)
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
		{"division after a variable named of", `
let of = 4; const x = of / 2; const m = require(process.argv[3]); const y = 1 / 3;
` + tail, true},
		{"regex holding a quote after export default", `
export default /'/; const m = require(process.argv[3]);
` + tail, true},
		{"regex holding a quote after a spread", `
function check(s) { return [.../'/.exec(s)]; } const m = require(process.argv[3]);
` + tail, true},
		{"regex holding a quote after a spaced less-than", `
function check(x, s) { return x < /'/.exec(s); } const m = require(process.argv[3]);
` + tail, true},
		{"regex holding a quote after a block", `
function check(s) { if (s) { s = s.trim(); } /'/.test(s); const m = require(process.argv[3]); return m; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"regex holding an escaped slash after yield", `
function* g(s) { yield /\//; const m = require(process.argv[3]); return m; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"regex holding an escaped slash after await", `
async function g(s) { await /\//; const m = require(process.argv[3]); return m; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"regex class holding two slashes after yield", `
function* g(s) { yield /[//]/; const m = require(process.argv[3]); return m; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"regex holding an escaped slash after of in a for await head", `
async function g(s) { for await (const x of /\//g.exec(s)) { require(process.argv[3]); } }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"regex holding an escaped slash after a block", `
function check(s) { if (s) { s = s.trim(); } /\//.test(s) && require(process.argv[3]); return s; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"regex ending in a quantifier after of in a for await head", `
async function g(s) { for await (const x of /\d+/g.exec(s)) { require(process.argv[3]); } // c
}
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"regex ending in a star after of in a for await head", `
async function g(s) { for await (const x of /a*/g.exec(s)) { require(process.argv[3]); } // c
}
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"regex holding an equals sign after of in a for await head, then a division", `
async function g(s) { for await (const x of /=/g.exec(s)) { require(process.argv[3]); } return 1 / 2; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"regex ending in a quantifier after yield", `
function* g(s) { yield /\d+/; require(process.argv[3]) // c
}
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"a variable named of divided in a for head", `
let of = 4;
for (let i = 0; i < of / 2; i++) require(process.argv[3])(i / 2);
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"a spaced JSX closing tag", `
const A = () => <div>x< /div>; const m = require(process.argv[3]); const B = () => <b>y</b>;
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"two JSX apostrophes around a require", `
function A() { return <p>Don't {require(process.argv[3]).parse("x")} won't</p>; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"two JSX apostrophes around an eval", `
function A(x) { return <p>It's {eval(x)}, isn't it</p>; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"two JSX apostrophes around a dynamic import", `
function A(x) { return <p>We're {import(x)} ready, aren't we</p>; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		// Template, comment and regex text naming a loader is read as code, since a misread
		// opener can make real code look like text; these over-declare by design.
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
		{"loader names in a regex body", `
function load(s) { return /require|import|eval/.test(s) ? s.trim() : s; }
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
		{"constructor of a function tagged flush against a template", `
const g = function () {};
function run(s) { return g.constructor^a${s}^; }
run(process.argv[3]);
` + tail, true},
		{"Function reached as [].constructor.constructor, tagged flush", `
function run(s) { return [].constructor.constructor^a${s}^; }
run(process.argv[3]);
` + tail, true},
		{"Function tagged flush against a template", `
function run(s) { return Function^a${s}^; }
run(process.argv[3]);
` + tail, true},
		{"optional constructor of a function tagged flush", `
const g = function () {};
function run(s) { return g?.constructor^a${s}^; }
run(process.argv[3]);
` + tail, true},
		{"new this.constructor tagged flush in a class method called on a function", `
class A { m(s) { return new this.constructor^a${s}^; } }
A.prototype.m.call(function () {}, process.argv[3]);
` + tail, true},
		{"typeof of require.bind tagged flush, then called", `
function run(s) { return typeof require.bind^x^(s); }
run(process.argv[3]);
` + tail, true},
		{"typeof of require.bind tagged flush, then called, after a JSX apostrophe", `
function A(s) { return <p>Don't {typeof require.bind^x^(s)}</p>; }
A(process.argv[3]);
` + tail, true},
		{"negated require.bind tagged flush, then called", `
function run(s) { return !require.bind^x^(s); }
run(process.argv[3]);
` + tail, true},
		{"a static import between a stray backtick in JSX text and a later template", `
const A = () => <p>Run ^npm i</p>;
import m from 'json5';
function B() { return ^ok^; }
` + tail, true},
		{"two JSX apostrophes around process.dlopen", `
function A(m, p) { return <p>Don't {process.dlopen(m, p)} won't</p>; }
function load(s) { return s.trim(); }
load(process.argv[2]);
`, true},
		{"strings holding braces", `
const t = '{ "a": 1 }';
const f = "{0} items";
function load(s) { return s.trim() + t + f; }
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
