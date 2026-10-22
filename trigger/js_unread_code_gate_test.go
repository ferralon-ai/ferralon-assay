package trigger

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
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
		{"constructor of a value and of this read, tested and assigned", "class Box { constructor(v) { this.v = v; } clone() { return new this.constructor(this.v); } }\nconst b = new Box(1);\nfunction Sub() {}\nSub.prototype.constructor = Sub;\nconst same = b.constructor === Box && b instanceof b.constructor && b.constructor.name !== '' && Object.getPrototypeOf(b).constructor !== Object;\nconst j = require('./plugins');", nil},
		{"eval and Function members tested", "const opts = {};\nconst j = require('./plugins');\nif (opts.eval) load('x');\nconst on = !opts.Function && opts.eval !== true;", nil},
		{"webpack's runtime require of an in-tree module", "const j = __non_webpack_require__('./plugins');", nil},
		{"arguments inside a function, as a member and as a key", "function first() { return arguments[0]; }\nconst info = { arguments: first.arguments };\nconst j = require('./plugins');", nil},
		{"local values exported under the names module, require and process", "const own = {};\nexport { own as module, own as require, own as process };\nconst j = require('./plugins');", nil},
		{"constructor as a class method and an object-literal key", "class Box { constructor(v) { this.v = v; } }\nfunction inherit(sub, sup) { sub.prototype = Object.create(sup && sup.prototype, { constructor: { value: sub, writable: true } }); }\nconst desc = { constructor: Box, f({ a }) { return a; } };\nconst j = require('./plugins');", nil},
		{"a prototype-pollution guard on a constructor key", "function set(o, k, v) { if (k === '__proto__' || k === 'constructor') return; o[k] = v; }\nconst name = Reflect.get(set, 'name');\nconst j = require('./plugins');", nil},
		{"arguments inside class methods", "class A { m() { return arguments[0]; } static s() { return arguments.length; } constructor() { this.n = arguments.length; } }\nconst j = require('./plugins');", nil},
		{"this.constructor constructed in an instance method and a prototype method", "class Box { constructor(v) { this.v = v; } clone() { return new this.constructor(this.v); } }\nfunction Foo(v) { this.v = v; }\nFoo.prototype.clone = function () { return new this.constructor(this.v); };\nclass Reg { static make() { return new this.constructor(); } }\nconst j = require('./plugins');", nil},
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
