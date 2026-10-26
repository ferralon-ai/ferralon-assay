package jsanalysis

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

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

		// W1
		{"Function reached through a parameter and one data key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nfunction invoke(r) { return r[k](process.argv[3])(); } invoke(g);\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W2-declaration
		{"Function reached from a local declaration", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W2-expression
		{"Function reached from a local expression", map[string]string{"app.js": "const j = { parse: String };\nconst g = function () {};\nconst k = process.argv[4]; g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W2-arrow
		{"Function reached from a local arrow", map[string]string{"app.js": "const j = { parse: String };\nconst g = () => {};\nconst k = process.argv[4]; g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W3-index
		{"Function reached through optional index", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\ng?.[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W3-call
		{"Function reached through optional call", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\ng[k]?.(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W3-both
		{"Function reached through optional both", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\ng?.[k]?.(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W4
		{"Function reached through a parenthesised inner index", map[string]string{"app.js": "const j = { parse: String };\nconst k = process.argv[4]; const g = {}; (g[k])[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W5
		{"Function reached through an aliased inner index", map[string]string{"app.js": "const j = { parse: String };\nconst k = process.argv[4]; const g = {}; const C = g[k]; C[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W6
		{"Function aliased from one data key and later called", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst F = g[k]; F(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W7
		{"Function passed from one data key to a callee", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nfunction invoke(F) { return F(process.argv[3])(); } invoke(g[k]);\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W8-return
		{"Function escaped through return", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nfunction pick(r) { return r[k]; } pick(g);\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W8-export
		{"Function escaped through export", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nexport const F = g[k];\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W8-array
		{"Function escaped through array", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst values = [g[k]];\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W8-object
		{"Function escaped through object", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst value = { F: g[k] };\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W8-spread
		{"Function escaped through spread", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst value = { ...g[k] };\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W9-call
		{"Function invoked through call", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\ng[k].call(null, process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W9-apply
		{"Function invoked through apply", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\ng[k].apply(null, [process.argv[3]])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W9-bind
		{"Function invoked through bind", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\ng[k].bind(null, process.argv[3])()();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W9-reflect
		{"Function invoked through reflect", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nReflect.apply(g[k], null, [process.argv[3]])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W10
		{"Function used as a template tag", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\ng[k]`return 1`();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W11
		{"Function constructed through one data key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nnew (g[k])(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W12
		{"Function reached through concatenated literal key pieces", map[string]string{"app.js": "const j = { parse: String };\n(function () {})['con' + 'structor'](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W13-concat
		{"Function reached through a data concat key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\ng['con' + process.argv[4]](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W13-template
		{"Function reached through a data template key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\ng[`con${process.argv[4]}`](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W14-const
		{"Function reached through a const key binding", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W14-ternary
		{"Function reached through a ternary key binding", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[5] ? 'name' : process.argv[4]; g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W14-or
		{"Function reached through a or key binding", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4] || 'name'; g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W14-nullish
		{"Function reached through a nullish key binding", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4] ?? 'name'; g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W15-length
		{"Function reached through a data object length member", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nfunction invoke(data) { return g[data.length](process.argv[3])(); } invoke({ length: k });\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W15-key
		{"Function reached through a data object key member", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nfunction invoke(data) { return g[data.key](process.argv[3])(); } invoke({ key: k });\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W16
		{"Function reached through a counter reassigned from data", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nlet i = 0; i++; if (process.argv[5]) i = k; g[i](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W17-for-in
		{"Function indexed by names from a different receiver through for-in", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst x = { [k]: 1 }; for (const name in x) { g[name](process.argv[3])(); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W17-keys
		{"Function indexed by names from a different receiver through Object.keys", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst x = { [k]: 1 }; for (const name of Object.keys(x)) { g[name](process.argv[3])(); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W18-names
		{"Function reached through prototype own names names", map[string]string{"app.js": "const j = { parse: String };\nconst p = Object.getPrototypeOf(function () {}); for (const name of Object.getOwnPropertyNames(p)) { p[name](process.argv[3])(); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W18-keys
		{"Function reached through prototype own names keys", map[string]string{"app.js": "const j = { parse: String };\nconst p = Object.getPrototypeOf(function () {}); for (const name of Reflect.ownKeys(p)) { p[name](process.argv[3])(); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W19
		{"Function inherited through an object literal prototype", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst r = { __proto__: g }; r[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W20
		{"Function inherited after a prototype write in the same file", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst r = {}; Object.setPrototypeOf(r, g); r[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W21
		{"Function inherited after a prototype write in another file", map[string]string{"app.js": "const j = { parse: String };\nimport { r } from './receiver.js';\nimport './mutate.js';\nconst k = process.argv[4]; r[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n", "mutate.js": "import { r } from './receiver.js'; function g() {} Object.setPrototypeOf(r, g);", "receiver.js": "export const r = {};"}, plugin.PartialReasonEvaluatedCode},

		// W21-local
		{"Function on a local plain receiver with a prototype channel elsewhere", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nimport './mutate.js';\nconst r = {}; r[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n", "mutate.js": "const other = {}; function g() {} Object.setPrototypeOf(other, g);"}, plugin.PartialReasonEvaluatedCode},

		// W22
		{"Function read from a receiver spreading unknown data", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nfunction invoke(data) { const r = { ...data }; return r[k](process.argv[3])(); } invoke({ [k]: g });\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W23
		{"Function read from a receiver reassigned from a parameter", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nfunction invoke(data) { let r = {}; r = data; return r[k](process.argv[3])(); } invoke(g);\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W24
		{"Function read from a method this bound to a function", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst holder = { invoke() { return this[k](process.argv[3])(); } }; holder.invoke.call(g);\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W25
		{"Function read from an imported in-tree binding", map[string]string{"app.js": "const j = { parse: String };\nimport { g } from './receiver.js'; const k = process.argv[4]; g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n", "receiver.js": "export function g() {}"}, plugin.PartialReasonEvaluatedCode},

		// W26
		{"Function read through an array coerced key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {} g[['constructor']](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W27
		{"Function read through Reflect get and an array coerced key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {} Reflect.get(g, ['constructor'])(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W28
		{"Function read through Reflect apply targeting Reflect get", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {} Reflect.apply(Reflect.get, null, [g, 'constructor'])(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W29-values
		{"Function read from descriptor enumeration values", map[string]string{"app.js": "const j = { parse: String };\nconst p = Object.getPrototypeOf(function () {}); const ds = Object.getOwnPropertyDescriptors(p); Object.values(ds).find(d => typeof d.value === \"function\").value(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W29-entries
		{"Function read from descriptor enumeration entries", map[string]string{"app.js": "const j = { parse: String };\nconst p = Object.getPrototypeOf(function () {}); const ds = Object.getOwnPropertyDescriptors(p); Object.entries(ds).find(pair => typeof pair[1].value === \"function\")[1].value(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W30
		{"Function read through Reflect get with a data key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nReflect.get(g, k)(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W31-Object-value
		{"Function read through Object descriptor value", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst p = Object.getPrototypeOf(g);Object.getOwnPropertyDescriptor(p, k).value(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W31-Object-get
		{"Function read through Object descriptor get", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst p = { get [k]() { return Object.getPrototypeOf(g)[k]; } };Object.getOwnPropertyDescriptor(p, k).get(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W31-Reflect-value
		{"Function read through Reflect descriptor value", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst p = Object.getPrototypeOf(g);Reflect.getOwnPropertyDescriptor(p, k).value(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W31-Reflect-get
		{"Function read through Reflect descriptor get", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst p = { get [k]() { return Object.getPrototypeOf(g)[k]; } };Reflect.getOwnPropertyDescriptor(p, k).get(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W32
		{"Function read through computed destructuring", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst { [k]: F } = g; F(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W33-alias
		{"Function read through a alias of Reflect get", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst get = Reflect.get; get(g, k)(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W33-destructure
		{"Function read through a destructure of Reflect get", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst { get } = Reflect; get(g, k)(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W34-callback
		{"Function getter escaped through callback", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nfunction use(get) { return get(g, k); } use(Reflect.get);\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W34-object
		{"Function getter escaped through object", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst api = { get: Reflect.get };\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// G5-Reflect-reclassified
		{"Reflect indexed by a data member", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {} const m = process.argv[4]; Reflect[m](g, process.argv[5])(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// G5-Object-reclassified
		{"Object indexed by a data member", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {} const m = process.argv[4]; Object[m](Object.getPrototypeOf(g), process.argv[5]).value(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W35-constructor-member
		{"Function reached through own-key enumeration of a constructor member", map[string]string{"app.js": "const j = { parse: String };\nconst r = { run: s => s, constructor: Function };\nfor (const k in r) { r[k](process.argv[3])(); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// W35-member-write
		{"Function reached through own-key enumeration after a member write", map[string]string{"app.js": "const j = { parse: String };\nconst r = { run: s => s };\nr.constructor = Function;\nfor (const k of Object.keys(r)) { r[k](process.argv[3])(); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-*: each row holds one key, receiver, prototype-channel or 2a guard on its own.
		// M-key-assignment
		{"Function reached through an assignment-expression key binding", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nlet x;\nconst k = (x = process.argv[4]); g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-generic
		{"Function reached through a generic call key binding", map[string]string{"app.ts": "const j = { parse: String };\nfunction g() {}\nfunction id<T>(v: T): T { return v; }\nconst k = id<string>(process.argv[4]); g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-Symbol-shadowed
		{"Function reached through a shadowed Symbol key binding", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst Symbol = (s) => s;\nconst k = Symbol(process.argv[4]); g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-undefined-shadowed
		{"Function reached through a parameter named undefined", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nfunction h(undefined) { g[undefined](process.argv[3])(); }\nh(process.argv[4]);\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-rebound
		{"Function reached through a key rebound by destructuring", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nlet k = 'name';\n[k] = [process.argv[4]];\ng[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-compound
		{"Function reached through a key extended with data", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nlet k = 'na';\nk += process.argv[4];\ng[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-import
		{"Function reached through an imported key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nimport k from 'key-name';\ng[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-top-var
		{"Function reached through a top-level var key rewritten on the global object", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nvar k = 'name';\nglobalThis.k = process.argv[4];\ng[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-symbol-description
		{"Function reached through a key destructured from a symbol description", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst { description: k } = Symbol(process.argv[4]);\ng[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-entries-value
		{"Function reached through an Object.entries value with a prototype channel", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst other = {};\nObject.setPrototypeOf(other, g);\nconst r = { a: process.argv[4] };\nfor (const [n, k] of Object.entries(r)) { r[k](process.argv[3])(); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-array-element
		{"Function reached through a data element of an iterated array", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nfor (const k of ['name', process.argv[4]]) { g[k](process.argv[3])(); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-Object-shadowed
		{"Function reached through a shadowed Object.keys with a prototype channel", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst other = {};\nObject.setPrototypeOf(other, g);\nconst Object = { keys: () => [process.argv[4]] };\nconst r = { name: 1 };\nfor (const k of Object.keys(r)) { r[k](process.argv[3])(); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-reduce
		{"Function reached through a reduce accumulator seeded with data", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\n['name'].reduce((k) => { g[k](process.argv[3])(); return k; }, process.argv[4]);\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-template-cut
		{"Function reached through a template whose substitution holds a comma", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = `x${0, process.argv[4]}`.slice(1); g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-key-template-escape
		{"Function reached through an escaped template piece", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = `\\x63${process.argv[4]}`; g[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-receiver-top-var
		{"Function reached through a top-level var receiver rewritten on the global object", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nvar r = { run: (s) => s };\nglobalThis.r = g;\nconst k = process.argv[4];\nr[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-receiver-rebound
		{"Function reached through a receiver rebound by destructuring", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nlet r = { run: (s) => s };\n[r] = [g];\nr[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-receiver-param-var
		{"Function reached through a parameter redeclared as a function-scoped var", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nfunction invoke(r) { r[k](process.argv[3])(); var r = { run: (s) => s }; } invoke(g);\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-receiver-constructor-key
		{"Code evaluated through a constructor member of an enumerated literal", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst r = { run: (s) => s, constructor: require('vm').runInThisContext };\nfor (const k in r) { r[k](process.argv[3]); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-receiver-quoted-constructor-key
		{"Code evaluated through a quoted constructor member of an enumerated literal", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst r = { run: (s) => s, 'constructor': require('vm').runInThisContext };\nfor (const k in r) { r[k](process.argv[3]); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-receiver-member
		{"Function reached through a member receiver named like a local literal", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst r = { run: (s) => s };\nconst x = { r: g };\nconst k = process.argv[4];\nx.r[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-enum-other-literal
		{"Function reached through keys enumerated from a different literal with a prototype channel", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst other = {};\nObject.setPrototypeOf(other, g);\nconst x = { constructor: 1 };\nconst r = { run: (s) => s };\nfor (const k in x) { r[k](process.argv[3])(); }\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-enum-parameter
		{"Code evaluated through keys enumerated from a parameter receiver", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nfunction h(r) { for (const k in r) { r[k](process.argv[3])(); } }\nh(require('vm'));\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-proto-hidden-text
		{"Function inherited through a prototype write in text the lexer blanks", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst r = {};\nconst el = <p>don't</p>; Object.setPrototypeOf(r, g);\nr[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-proto-hidden-receiver
		{"Function on a plain receiver in text the lexer blanks with a prototype channel elsewhere", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst other = {};\nObject.setPrototypeOf(other, g);\nconst k = process.argv[4];\nconst el = <p>don't</p>; const r = {}; r[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-proto-computed-write
		{"Function inherited through a computed write with a data key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst r = {};\nr[process.argv[5]] = g;\nr[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-proto-quoted-key
		{"Function inherited through a quoted __proto__ key in a prototype value", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst r = {};\nObject.setPrototypeOf(r, { '__proto__': g });\nr[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-proto-bare-key
		{"Function inherited through a __proto__ key in a prototype value", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst r = {};\nObject.setPrototypeOf(r, { __proto__: g });\nr[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-proto-setPrototypeOf-alias
		{"Function inherited through an aliased setPrototypeOf", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst r = {};\nconst sp = Object.setPrototypeOf;\nsp(r, g);\nr[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-proto-Reflect.set-spread
		{"Function inherited through Reflect.set with spread arguments", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst r = {};\nconst args = [r, '__proto__', g];\nReflect.set(...args);\nr[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-proto-Reflect.set-key
		{"Function inherited through Reflect.set with a data key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst r = {};\nReflect.set(r, process.argv[5], g);\nr[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-proto-member-assign
		{"Function inherited through a __proto__ assignment", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst r = {};\nr.__proto__ = g;\nr[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-2a-package-path
		{"Function reached through a constructor path array handed to a package", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst _ = require('lodash');\n_.get(g, ['constructor'])(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// M-2a-concat
		{"Function reached through a constructor path array copied by concat", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst _ = require('lodash');\n_.get(g, ['constructor'].concat([]))(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// X*: second-hop keys, literal-bracket reflective members, block functions over a var and
		// private names. E*p and K24p hold the enumeration and callback-parameter guards.
		// X1
		{"Function invoked through a second key bound to call", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst c = 'call';\ng[k][c](null, process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X2
		{"Function invoked through a parenthesised second key naming call", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\ng[k][('call')](null, process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X3
		{"Function invoked through a concatenated second key naming call", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\ng[k]['ca' + 'll'](null, process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X5
		{"Function invoked through apply on a const holding a data-keyed read", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst F = g[k];\nconst c = 'apply';\nF[c](null, [process.argv[3]])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X6
		{"Function bound through a second key bound to bind", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst c = 'bind';\ng[k][c](null, process.argv[3])()();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X9
		{"Function read through Reflect get spelled with a literal bracket", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nReflect['get'](g, k)(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X10b
		{"Function read through an Object descriptor spelled with a literal bracket", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nObject[\"getOwnPropertyDescriptor\"](Object.getPrototypeOf(g), k).value(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X11
		{"Function read through Reflect reached by a literal bracket on globalThis", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nglobalThis['Reflect'].get(g, k)(process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X12
		{"Function inherited through Reflect setPrototypeOf spelled with a literal bracket", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst o = {};\nReflect['setPrototypeOf'](o, g);\no[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X13
		{"Function inherited through Object setPrototypeOf spelled with a literal bracket", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst o = {};\nObject['setPrototypeOf'](o, g);\no[k](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X17
		{"Function reached through a var receiver overwritten by a block function declaration", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nfunction run(k) { var o = {}; if (k) { function o() {} } return o[k](process.argv[3])(); }\nrun(process.argv[4]);\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X18
		{"Function reached through a private field named like a local literal", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nclass A { #o = g; m(k) { const o = {}; return this.#o[k](process.argv[3])(); } }\nnew A().m(process.argv[4]);\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// X18-key
		{"Function reached through a private field key named like a safe local key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nclass A { #k = process.argv[4]; m() { const k = 'name'; return g[this.#k](process.argv[3])(); } }\nnew A().m();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function read through a descriptor value named by a concatenated key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst v = 'val' + 'ue';\nObject.getOwnPropertyDescriptor(Object.getPrototypeOf(g), k)[v](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function read through a descriptor get named by a concatenated key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4];\nconst v = 'g' + 'et';\nObject.getOwnPropertyDescriptor(Object.getPrototypeOf(g), k)[v](process.argv[3])();\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// E01p
		{"Function enumerated from a literal after a member write of a reflective read", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst o = { b: 0 };\no.b = Reflect['get'](g, process.argv[4]);\nconst p = {};\nObject.setPrototypeOf(p, process.env);\nObject.keys(o).forEach(k => o[k](process.argv[3])());\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// E02p
		{"Function enumerated from a literal after a computed write of a reflective read", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst o = { b: 0 };\no['b'] = Reflect['get'](g, process.argv[4]);\nconst p = {};\nObject.setPrototypeOf(p, process.env);\nObject.keys(o).forEach(k => o[k](process.argv[3])());\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// E03p
		{"Function enumerated from a literal handed to a call that writes it", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst o = { b: 0 };\nfunction put(t) { t.b = Reflect['get'](g, process.argv[4]); }\nput(o);\nconst p = {};\nObject.setPrototypeOf(p, process.env);\nObject.keys(o).forEach(k => o[k](process.argv[3])());\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// E04p
		{"Function enumerated from a literal written through an alias", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst o = { b: 0 };\nconst t = o;\nt.b = Reflect['get'](g, process.argv[4]);\nconst p = {};\nObject.setPrototypeOf(p, process.env);\nObject.keys(o).forEach(k => o[k](process.argv[3])());\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
		// K24p
		{"Function reached through an iterated array rewritten through its callback", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\n['a'].forEach((k, i, arr) => { arr[0] = process.argv[4]; g[arr](process.argv[3])(); });\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// E01w
		{"Function enumerated from a literal after a member write of a read keyed under with", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst c = 'name';\nconst o = { b: 0 };\nwith ({ c: process.argv[4] }) { o.b = g[c]; }\nconst p = {};\nObject.setPrototypeOf(p, process.env);\nObject.keys(o).forEach(k => o[k](process.argv[3])());\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// E02w
		{"Function enumerated from a literal after a computed write of a read keyed under with", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst c = 'name';\nconst o = { b: 0 };\nwith ({ c: process.argv[4] }) { o['b'] = g[c]; }\nconst p = {};\nObject.setPrototypeOf(p, process.env);\nObject.keys(o).forEach(k => o[k](process.argv[3])());\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// E03w
		{"Function enumerated from a literal handed to a call that writes a read keyed under with", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst c = 'name';\nconst o = { b: 0 };\nfunction put(t) { with ({ c: process.argv[4] }) { t.b = g[c]; } }\nput(o);\nconst p = {};\nObject.setPrototypeOf(p, process.env);\nObject.keys(o).forEach(k => o[k](process.argv[3])());\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// E04w
		{"Function enumerated from a literal written through an alias with a read keyed under with", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst c = 'name';\nconst o = { b: 0 };\nconst t = o;\nwith ({ c: process.argv[4] }) { t.b = g[c]; }\nconst p = {};\nObject.setPrototypeOf(p, process.env);\nObject.keys(o).forEach(k => o[k](process.argv[3])());\nfunction load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// A1
		{"Function reached through Reflect indexed by a const naming get", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'get'; Reflect[m](g, k)(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// A2
		{"Function reached through Reflect indexed by a concatenation naming get", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; Reflect['g' + 'et'](g, k)(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// A3
		{"Function reached through Reflect indexed by a parenthesised get", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; Reflect[('get')](g, k)(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// A5
		{"Function reached through a prototype set by Object indexed by a const", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'setPrototypeOf'; const o = {}; Object[m](o, g); o[k](process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// A6
		{"Function reached through a descriptor from Object indexed by a concatenation", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; Object['getOwnProperty' + 'Descriptor'](Object.getPrototypeOf(g), k).value(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// A25
		{"Function reached through Reflect.apply of Reflect indexed by a const", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'get'; Reflect.apply(Reflect[m], null, [g, k])(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// U1
		{"Function reached through Reflect indexed by a key that never resolves", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; Reflect[process.argv[5]](g, k)(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// S1
		{"Function reached through Reflect read as a member of the global", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'get'; globalThis.Reflect[m](g, k)(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// S2
		{"Function reached through Reflect read from the global by a literal key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'get'; globalThis['Reflect'][m](g, k)(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// S3
		{"Function reached through Reflect read from a function's this by a const key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'get'; const r = 'Reflect'; function f() { return this[r][m](g, k)(process.argv[3])(); } f();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// S4
		{"Function reached through a parenthesised Object", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'getOwnPropertyDescriptor'; (Object)[m](Object.getPrototypeOf(g), k).value(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// S5
		{"Function reached through Object as the last operand of a comma", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'getOwnPropertyDescriptor'; (0, Object)[m](Object.getPrototypeOf(g), k).value(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// S6
		{"Function reached through Reflect indexed by optional chaining", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'get'; Reflect?.[m](g, k)(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// S7
		{"Function reached through Object handed to a function as an argument", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'getOwnPropertyDescriptor'; function f(O) { return O[m](Object.getPrototypeOf(g), k).value(process.argv[3])(); } f(Object);function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// S8
		{"Function reached through Object held in an object literal", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'getOwnPropertyDescriptor'; const o = { O: Object }; o.O[m](Object.getPrototypeOf(g), k).value(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// S9
		{"Function reached through a class extending Object indexed by a const", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'getOwnPropertyDescriptor'; class X extends Object {} X[m](Object.getPrototypeOf(g), k).value(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// S10
		{"Function reached through Reflect.get reading Object under a const key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'getOwnPropertyDescriptor'; Reflect.get(Object, m)(Object.getPrototypeOf(g), k).value(process.argv[3])();function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// A12
		{"Function bound over a var receiver by an if body without braces", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nfunction run(k) { var o = {}; if (k) function o() {} return o[k](process.argv[3])(); } run(process.argv[4]);function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// A13
		{"Function bound over a var receiver by a switch case", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nfunction run(k) { var o = {}; switch (1) { case 1: function o() {} } return o[k](process.argv[3])(); } run(process.argv[4]);function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// A14
		{"Function bound over a var receiver by a labelled declaration", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nfunction run(k) { var o = {}; { l: function o() {} } return o[k](process.argv[3])(); } run(process.argv[4]);function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// B1
		{"Function bound over a var receiver from a doubly nested block", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nfunction run(k) { var o = {}; { { function o() {} } } return o[k](process.argv[3])(); } run(process.argv[4]);function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// B2
		{"Function bound over a var receiver by a do-while body", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nfunction run(k) { var o = {}; do { function o() {} } while (0); return o[k](process.argv[3])(); } run(process.argv[4]);function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// U2-with
		{"Function reached through Reflect indexed by a const a with statement rebinds", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'has'; with ({ m: 'get' }) { Reflect[m](g, k)(process.argv[3])(); }function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// S11
		{"Function reached through Reflect read from a function's this by a parameter key", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; const m = 'get'; function f(r) { return this[r][m](g, k)(process.argv[3])(); } f('Reflect');function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},

		// U3-let
		{"Function reached through Reflect indexed by a let a loop update rebinds", map[string]string{"app.js": "const j = { parse: String };\nfunction g() {}\nconst k = process.argv[4]; for (let m = 'has'; m; m = m === 'has' ? 'get' : '') { if (m === 'get') Reflect[m](g, k)(process.argv[3])(); }function load(s) { return j.parse(s); }\nload(process.argv[2]);\n"}, plugin.PartialReasonEvaluatedCode},
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
		{"static prefix into the package", map[string]string{"app.js": `
function load(n, s) { return require('json5/' + n).parse(s); }
load(process.argv[2], process.argv[3]);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"template prefix into the package", map[string]string{"app.js": "\n" +
			"async function load(n, s) { const J = await import(`json5/${n}`); return J.parse(s); }\n" +
			"load(process.argv[2], process.argv[3]);\n"}, plugin.PartialReasonDynamicImportSpecifier},
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
		{"dynamic import spread into an object", map[string]string{"app.js": `
function load(s, n) { const J = { ...import(` + "`./${n}`" + `) }; return J; }
load(process.argv, 'json5');
`}, plugin.PartialReasonDynamicImportSpecifier},
		{"dynamic import after a number ending in a dot", map[string]string{"app.js": `
function load(s, n) { var x = 1.
import(` + "`./${n}`" + `); return x; }
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
		{"module aliased then indexed", map[string]string{"app.js": `
const m = typeof module === 'object' && module;
function load(s) { return m[process.argv[3]]('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"module destructured for a loader member", map[string]string{"app.js": `
const { constructor: Module } = module;
function load(s) { return Module._load('json5').parse(s); }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"process reached through the global and indexed", map[string]string{"app.js": `
const m = { exports: {} };
globalThis['process'][process.argv[3]](m, './x.node');
function load(s) { return m.exports.parse(s); }
load(process.argv);
`}, plugin.PartialReasonUnresolvedModule},
		{"imports branch under a non-default condition", map[string]string{
			"package.json": `{"name":"fixture","imports":{"#j":{"worker":"json5","default":"./util.js"}},"dependencies":{"json5":"2.2.1"}}`,
			"util.js":      "module.exports = { parse(s) { return s; } };\n",
			"app.js": `
const j = require('#j');
function load(s) { return j.parse(s); }
load(process.argv);
`}, ""},
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
		{"Function body hiding a call behind a regular expression after return", map[string]string{"app.js": `
var f = Function("x", "return /'/, eval(x) //'");
f(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body hiding a call behind a regular expression after typeof", map[string]string{"app.js": `
var f = new Function("x", "return typeof /'/, eval(x) //'");
f(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body hiding a call behind a comment ended by a line separator", map[string]string{"app.js": `
var f = Function("x", "//'` + "\u2028" + `return eval(x) //'");
f(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body with a slash", map[string]string{"app.js": `
Function('a', 'b', 'return a / b');
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"require after a member named function and a line break", map[string]string{"app.js": `
var o = { function: 1 };
o.function
require(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"require after a private member named function and a line break", map[string]string{"app.js": `
class A { #function = 1; run() { this.#function
require(process.argv[2]); } }
new A().run();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"Function argument spliced in behind a comment ended by a line separator", map[string]string{"app.js": `
var f = Function("x", "return x" // ` + "\u2028" + ` + process.argv[2]
); f(1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function argument spliced in behind a comment ended by a carriage return", map[string]string{"app.js": `
var f = Function("x", "return x" // ` + "\r" + ` + process.argv[2]
); f(1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"new Function argument spliced in behind a comment ended by a paragraph separator", map[string]string{"app.js": `
var f = new Function("x", "return x" // ` + "\u2029" + ` + process.argv[2]
); f(1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function body spliced in behind a comment ended by a line separator", map[string]string{"app.js": `
Function("return 1" // ` + "\u2028" + ` + process.argv[2]
)();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function parameter list from input behind a comment ended by a line separator", map[string]string{"app.js": `
var f = Function(// ` + "\u2028" + ` process.argv[2],
"return 1"); f(1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call called behind a comment ended by a line separator", map[string]string{"app.js": `
var f = Function.call // ` + "\u2028" + ` (null, process.argv[2])
; f();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call.bind called behind a comment ended by a line separator", map[string]string{"app.js": `
var g = Function.call.bind // ` + "\u2028" + ` (Function)
; g(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"constructor of Function.call", map[string]string{"app.js": `
Function.call.constructor(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"constructor of Function.bind", map[string]string{"app.js": `
Function.bind.constructor(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"constructor of Function.apply", map[string]string{"app.js": `
Function.apply.constructor(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"constructor of Function.call by a literal key", map[string]string{"app.js": `
Function.call['constructor'](process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call indexed by a computed key", map[string]string{"app.js": `
Function.call[process.argv[3]](process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call indexed optionally", map[string]string{"app.js": `
Function.call?.['constructor'](process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call called optionally", map[string]string{"app.js": `
Function.call?.(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"constructor of Function.call aliased", map[string]string{"app.js": `
var C = Function.call.constructor; C(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call parenthesised then called", map[string]string{"app.js": `
(Function.call)(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call parenthesised twice then called", map[string]string{"app.js": `
((Function.call))(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.apply parenthesised then called", map[string]string{"app.js": `
(Function.apply)(null, [process.argv[2]])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.bind parenthesised then called", map[string]string{"app.js": `
(Function.bind)(null, process.argv[2])()();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call parenthesised then indexed", map[string]string{"app.js": `
(Function.call)['constructor'](process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call non-null asserted then called", map[string]string{"app.ts": `
Function.call!(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call called with a type argument", map[string]string{"app.ts": `
Function.call<any>(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call cast then called", map[string]string{"app.ts": `
(Function.call as any)(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call called optionally after a space", map[string]string{"app.js": `
Function.call?. (null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call called optionally across a line break", map[string]string{"app.js": `
Function. call?.
(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call indexed optionally after a space", map[string]string{"app.js": `
Function.call?. [process.argv[3]](process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call indexed optionally by a literal key after a space", map[string]string{"app.js": `
Function.call?. ['constructor'](process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function called optionally after a space", map[string]string{"app.js": `
Function?. (process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"constructor of a member of Function.call", map[string]string{"app.js": `
Function.call.toString.constructor(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"constructor of a bound Function.call", map[string]string{"app.js": `
Function.call.bind(null).constructor(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function parenthesised then called", map[string]string{"app.js": `
(Function)(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call parenthesised, cast, then called", map[string]string{"app.ts": `
((Function.call) as any)(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call checked with satisfies then called", map[string]string{"app.ts": `
(Function.call satisfies any)(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call parenthesised then read for its constructor", map[string]string{"app.js": `
(Function.call).constructor(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call tagged after a space", map[string]string{"app.js": `
Function.call ` + "`return process`" + `;
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a called Function.bind.apply chain tagged after a space", map[string]string{"app.js": `
Function.bind.apply(null, [null]) ` + "`x`" + `;
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call followed by an unlisted token", map[string]string{"app.js": `
var f = Function.call
+process.argv[2];
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call tagged on the next line", map[string]string{"app.js": `
var f = Function.call
` + "`return process`" + `;
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call cast on the next line", map[string]string{"app.ts": `
var f = (Function.call
as any)(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call cast with satisfies on the next line", map[string]string{"app.ts": `
var f = (Function.call
satisfies any)(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function member spelled with a unicode escape", map[string]string{"app.js": `
Function.\u0063onstructor(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"parenthesised Function called once through call", map[string]string{"app.js": `
var g = (Function).call(null, process.argv[2]);
g();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"constructor of Function", map[string]string{"app.js": `
Function.constructor(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"constructor of Function by a literal key", map[string]string{"app.js": `
Function['constructor'](process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global returned by a declared function indexed inline", map[string]string{"app.js": `
function G() { return this; }
G()[process.argv[2]](1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global returned by a declared function indexed inline in an initializer", map[string]string{"app.js": `
function G() { return this; }
var r = G()[process.argv[2]](1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global returned by a declared function exported", map[string]string{"app.js": `
function G() { return this; }
module.exports = G();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global returned by a declared function handed on", map[string]string{"app.js": `
function G() { return this; }
console.log(G());
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"typeof require called behind a comment ended by a line separator", map[string]string{"app.js": `
var t = typeof require // ` + "\u2028" + ` (process.argv[2])
;
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonComputedRequireSpecifier},
		{"computed key on globalThis behind a comment ended by a line separator", map[string]string{"app.js": `
globalThis // ` + "\u2028" + ` [process.argv[3]](process.argv[2])
;
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
var e = self.Function;
function load(s) { return e(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name bound by a for-in header, read after the loop", map[string]string{"app.js": `
const o = {};
for (let global in o) {}
const e = global.Function;
function load(s) { return e(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name bound by a for header in a function, read after the loop", map[string]string{"app.js": `
function load(s) {
  for (let self = 0; self < 1; self++) {}
  var e = self.Function;
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
const e = window.Function;
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
const e = self.Function;
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
var e = c ? window => 1 : window.Function;
function load(s) { return e(s); }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name as an arrow parameter in a nested ternary branch", map[string]string{"app.js": `
const c = process.env.X;
var e = c ? window => (c ? 1 : 2) : c ? 0 : window.Function;
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
		{"global var after an expression ending in module, before a do block", map[string]string{"app.js": `
var m = module
do { var self; var e = self.Function; e(process.argv[2]); } while (0);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global var after an assignment ending in module, in an else block", map[string]string{"app.js": `
if (process.env.X) x = module
else { var self; var e = self.Function; e(process.argv[2]); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global var after module.exports, in a try block", map[string]string{"app.js": `
var x = module.exports
try { var self; var e = self.Function; e(process.argv[2]); } catch (err) {}
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global var after a name namespace, in a plain block", map[string]string{"app.js": `
var namespace = 1, x
x = namespace
{ var self; var e = self.Function; e(process.argv[2]); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global past an arrow with JSX text holding a question mark", map[string]string{"app.jsx": `
var e = process.env.X ? window => <p>why?</p>
  : window.Function; e(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global past a TSX arrow with JSX text holding a question mark", map[string]string{"app.tsx": `
var e = process.env.X ? window => <p>why?</p>
  : window.Function; e(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global in a case block after a call in the label", map[string]string{"app.js": `
switch (process.env.X) { case String(self): { var e = self.Function; e(process.argv[2]); } }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global in an object literal after a ternary call branch", map[string]string{"app.js": `
var o = process.env.X ? load(window) : { e: window.Function }; o.e(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global in a block after a call statement", map[string]string{"app.js": `
load(self)
{ var e = self.Function; e(process.argv[2]); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global in a block after an indexed call statement", map[string]string{"app.js": `
var a = [load]; a[0](self)
{ var e = self.Function; e(process.argv[2]); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global in a block after a yield", map[string]string{"app.js": `
function* g() { yield (self)
{ var e = self.Function; e(process.argv[2]); } }
g().next();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global in a block after a member call named catch", map[string]string{"app.js": `
var p = Promise.resolve(); p.catch(self)
{ var e = self.Function; e(process.argv[2]); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this in a block after a member named class", map[string]string{"app.js": `
var o = {}; o.class
{ var e = this.eval; e(process.argv[2]); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global after a TypeScript function type naming it", map[string]string{"app.ts": `
const f: (self: any) => any = self.Function;
f(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"computed key destructured from a Function-built global", map[string]string{"app.js": `
var { [process.argv[3]]: f } = Function('return this')(); f(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function key destructured from a Function-built global", map[string]string{"app.js": `
var { Function: F } = Function('return this')(); F(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"computed key destructured in an in-place parameter from a Function-built global", map[string]string{"app.js": `
(function ({ [process.argv[3]]: f }) { f(process.argv[2]); })(Function('return this')());
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function key destructured from globalThis", map[string]string{"app.js": `
const { Function: F } = globalThis; F(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"computed key destructured from globalThis", map[string]string{"app.js": `
const { [process.argv[3]]: f } = globalThis; f(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function-built global stored through a chained member assignment", map[string]string{"app.js": `
var o = {}; var g = o.x = Function('return this')(); o.x[process.argv[2]](1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function-built global stored into module.exports through a chained assignment", map[string]string{"app.js": `
var root = module.exports = Function('return this')();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function-built global stored into a member inside parentheses", map[string]string{"app.js": `
var o = {}; var g = (o.x = Function('return this')());
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"this of a function called with a Function-built global, aliased and indexed", map[string]string{"app.js": `
(function () { var s = this; s[process.argv[2]](1); }).call(Function('return this')());
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"this of a function called with a Function-built global, indexed and returned", map[string]string{"app.js": `
var r = (function () { return this[process.argv[2]]; }).call(Function('return this')()); r(1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"this of a function called with globalThis, aliased and indexed", map[string]string{"app.js": `
(function () { var s = this; s[process.argv[2]](1); }).call(globalThis);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"this of a function called in place, aliased and indexed", map[string]string{"app.js": `
(function () { var s = this; s[process.argv[2]](1); })();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name holding the this a function called in place returns", map[string]string{"app.js": `
var self = (function () { return this; })(); var e = self.Function; e(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"name holding the this a function called in place returns, indexed", map[string]string{"app.js": `
var g = (function () { return this; })(); g[process.argv[2]](1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name holding the this a declared function returns", map[string]string{"app.js": `
function G() { return this; }
var global = G(); var e = global.Function; e(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name from a type-only import of as", map[string]string{"util.ts": "export const as = 1;\n", "app.ts": `
import { type as as self } from './util';
var e = self.Function; e(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global indexed in a call's argument before a block on the next line", map[string]string{"app.js": `
load(self[process.argv[2]](1))
{ }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global named by a member read in a call's argument before a block on the next line", map[string]string{"app.js": `
load(self.x)
{ self[process.argv[2]](1); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this in a block after a call of a member named function", map[string]string{"app.js": `
var o = {};
o.function(1)
{ var g = this; g[process.argv[2]](1); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this in a block after an assignment of a name interface", map[string]string{"app.js": `
var interface = 1, y
y = interface
{ var g = this; g[process.argv[2]](1); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this in an else block after a test of a name interface", map[string]string{"app.js": `
var interface = {}, b
if (process.env.X) b = interface instanceof Object
else { var g = this; g[process.argv[2]](1); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this in a block after a statement interface", map[string]string{"app.js": `
var interface = 1;
interface
{ var g = this; g[process.argv[2]](1); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this in a block after a call in a labelled block", map[string]string{"app.js": `
L: {
  m(1)
  { var g = this; g[process.argv[2]](1); }
}
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this in a block after a call in an else block", map[string]string{"app.js": `
if (process.env.X) {} else {
  m(1)
  { var g = this; g[process.argv[2]](1); }
}
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global var in a block after a name namespace and a name on separate lines", map[string]string{"app.ts": `
var namespace = 1;
namespace
N {
  var self; self[process.argv[2]](1);
}
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global var in a do block after else", map[string]string{"app.js": `
if (process.env.X) 0; else do { var self; self[process.argv[2]](1); } while (0);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global destructured by its key require", map[string]string{"app.js": `
const { require: r } = globalThis;
r(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a function of a namespace nested in a dotted declare namespace", map[string]string{"app.ts": `
declare namespace A.B { namespace C { function self(): void; } }
self[process.argv[2]](1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global reached as a member of a global, then eval", map[string]string{"app.js": `
var e = globalThis.global.Function;
e(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global reached as a member of itself, indexed", map[string]string{"app.js": `
window.window[process.argv[2]](1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global destructured by a quoted Function key", map[string]string{"app.js": `
var { 'Function': F } = globalThis;
F(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global destructured by a quoted eval key", map[string]string{"app.js": `
var { "eval": e } = globalThis;
e(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global destructured by a quoted require key", map[string]string{"app.js": `
var { 'require': r } = globalThis;
r(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global into a parameter destructured by a quoted key", map[string]string{"app.js": `
(function ({ 'Function': F }) { F(process.argv[2])(); })(globalThis);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global var in a block after a call statement, used after it", map[string]string{"app.js": `
load(1)
{ var g = globalThis; }
g[process.argv[2]](1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global assigned to a var in a block after a call statement, used after it", map[string]string{"app.js": `
load(1)
{ var g; g = globalThis; }
g[process.argv[2]](1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global let of a for header, used in the update", map[string]string{"app.js": `
var i = 0;
for (let g = globalThis; i < 1; i++, g[process.argv[2]](1)) {}
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global let of a for header, used in the test", map[string]string{"app.js": `
for (let g = globalThis; g[process.argv[2]](1); ) { break; }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name in a call after a member named default", map[string]string{"app.js": `
var x = exports.default
{
  load(window)
  { var e = window.Function; e(process.argv[2]); }
}
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name declared as a function in a strict block", map[string]string{"app.js": `
'use strict';
if (process.env.X) { function self() {} }
var e = self.Function;
e(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name declared as a function in a module block", map[string]string{"app.mjs": `
if (process.env.X) { function self() {} }
var e = self.Function;
e(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"eval read off a shadowing local of a global's name", map[string]string{"app.js": `
var o = { g: globalThis };
var self = o.g;
var e = self.eval;
e(process.argv[2]);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global reached through a chain of global names, indexed", map[string]string{"app.js": `
globalThis.window.self[process.argv[2]](1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"plain function's this in an object beside a key named class", map[string]string{"app.js": `
var o = { class: 1, y: { v: this[process.argv[2]](process.argv[3]) } };
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name bound by an import alias inside a TypeScript namespace, used outside it", map[string]string{"app.ts": `
namespace N { import self = Foo.bar; }
export const x = self[process.argv[2]](1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this in a block after a member named return", map[string]string{"app.js": `
var o = {}; o.return
{ load(1)
{ var e = this.eval; e(process.argv[2]); } }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"top-level this in a block after a postfix increment", map[string]string{"app.js": `
var x = 0; x++
{ load(1)
{ var e = this.eval; e(process.argv[2]); } }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global reached through a chain of global names, handed on", map[string]string{"app.js": `
load(globalThis.self);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name given a value by a var in a block after a call statement, used after it", map[string]string{"app.js": `
function f() {
  load(a)
  { var self = { a: 1 }; }
  return self[process.argv[2]](1);
}
f();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"global name given a value by a for header with an unbraced body, used after the loop", map[string]string{"app.js": `
for (let self = { a: 1 }; process.env.X;) load(self);
self[process.argv[2]](1);
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call bound", map[string]string{"app.js": "const has = Function.call.bind(Object.prototype.hasOwnProperty);" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.bind applied", map[string]string{"app.js": "function make(Parent, args) { return new (Function.bind.apply(Parent, args))(); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.call applied", map[string]string{"app.js": "function push() { return Function.call.apply(Array.prototype.push, arguments); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.bind as a polyfill fallback", map[string]string{"app.js": "const bind = Function.bind || function bind(that) { return that; };" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.call handed on", map[string]string{"app.js": "function ctx(fn, that) { return fn; }\nconst c = ctx(Function.call, load);" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.call compared", map[string]string{"app.js": "if (Function.call !== undefined) { load(); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.call handed on in parentheses", map[string]string{"app.js": "function ctx(fn) { return fn; }\nconst c = ctx((Function.call));" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.call in an array and an object", map[string]string{"app.js": "const fns = [Function.call];\nconst o = { c: Function.call };" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.call in nullish, ternary, logical and comparison operators", map[string]string{"app.js": "const a = Function.call ?? null;\nconst b = a ? Function.call : null;\nconst c = Function.call === a, d = Function.call !== b, e = Function.call >= 0, f = Function.call & 1;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.call as the last token", map[string]string{"app.js": "let f;\nf = Function.call" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.call ending a statement with no semicolon", map[string]string{"app.js": "const f = Function.call\nconst g = Function.bind\nmodule.exports = { f, g }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"a called Function.call.bind chain in a logical operator", map[string]string{"app.js": "function f() {}\nconst ok = Function.call.bind(f) && true;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function member read optionally", map[string]string{"app.js": "const n = Function?.length;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"a Function.call.call chain called optionally", map[string]string{"app.js": "function f() {}\nconst r = Function.call.call?.(f);" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"a Function.call.call chain called optionally after a space", map[string]string{"app.js": "function f() {}\nconst r = Function.call.call?. (f);" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function compared", map[string]string{"app.js": "function isCtor(f) { return f instanceof Function || (Function === f); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype.constructor called", map[string]string{"app.js": "Function.prototype.constructor(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype constructor read by a literal key", map[string]string{"app.js": "Function.prototype['constructor'](process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype indexed by a computed key", map[string]string{"app.js": "const k = process.argv[3];\nFunction.prototype[k](process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"a member of Function as instanceof's operand", map[string]string{"app.js": "function f(x) { return x instanceof Function.call; }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function indexed as instanceof's operand", map[string]string{"app.js": "function f(x, k) { return x instanceof Function[k]; }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function called as instanceof's operand", map[string]string{"app.js": "function f(x) { return x instanceof Function(process.argv[2]); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function non-null asserted as instanceof's operand", map[string]string{"app.js": "function f(x) { return x instanceof Function!.constructor(process.argv[2])(); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function as instanceof's operand tagging a template", map[string]string{"app.js": "function f(x) { return x instanceof Function `x`; }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype held as a value", map[string]string{"app.js": "var p = Function.prototype;\np.constructor(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype.call held as a value", map[string]string{"app.js": "var c = Function.prototype.call;\nc.constructor(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype.call read but not called", map[string]string{"app.js": "const c = [Function.prototype.call];" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype.call's constructor read", map[string]string{"app.js": "Function.prototype.call.constructor(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype.apply.call handed Function", map[string]string{"app.js": "Function.prototype.apply.call(Function, null, [process.argv[2]])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype.apply.call handed the global's Function", map[string]string{"app.js": "Function.prototype.apply.call(globalThis.Function, null, [process.argv[2]])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype read optionally", map[string]string{"app.js": "Function.prototype?.constructor(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance builtin's constructor read", map[string]string{"app.js": "Function.prototype[Symbol.hasInstance].constructor(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance builtin indexed", map[string]string{"app.js": "Function.prototype[Symbol.hasInstance]['constructor'](process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance builtin read optionally", map[string]string{"app.js": "Function.prototype[Symbol.hasInstance]?.constructor(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance builtin non-null asserted", map[string]string{"app.js": "Function.prototype[Symbol.hasInstance]!.constructor(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance builtin tagging a template", map[string]string{"app.js": "const f = Function.prototype[Symbol.hasInstance] `x`;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read through a declared Symbol", map[string]string{"app.js": "var Symbol = { hasInstance: 'constructor' };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read through a Symbol parameter", map[string]string{"app.js": "function f(Symbol) { return Function.prototype[Symbol.hasInstance]; }\nf({ hasInstance: 'constructor' })(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read through a function named Symbol", map[string]string{"app.js": "function Symbol() {}\nSymbol.hasInstance = 'constructor';\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read through a generator named Symbol", map[string]string{"app.js": "function* Symbol() {}\nSymbol.hasInstance = 'constructor';\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read through a Symbol a with statement scopes", map[string]string{"app.js": "var o = {};\no.Symbol = { hasInstance: 'constructor' };\nwith (o) { var h = Function.prototype[Symbol.hasInstance]; }\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype indexed by another well-known symbol", map[string]string{"app.js": "var h = Function.prototype[Symbol.iterator];" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype.call.call read but not called", map[string]string{"app.js": "const cc = [Function.prototype.call.call];" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype indexed by an expression starting with Symbol.hasInstance", map[string]string{"app.js": "Function.prototype[Symbol.hasInstance ? 'constructor' : 'x'](process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype indexed by a comma expression starting with Symbol.hasInstance", map[string]string{"app.js": "Function.prototype[Symbol.hasInstance, ('constructor')](process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read through a Symbol a with statement scopes from parsed data", map[string]string{"app.js": "var o = JSON.parse(process.argv[3]);\nwith (o) { var h = Function.prototype[Symbol.hasInstance]; }\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function after instanceof in an HTML open comment", map[string]string{"app.js": "var g = <!-- instanceof\nFunction;\ng(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function after instanceof in an HTML close comment", map[string]string{"app.js": "var g =\n--> instanceof\nFunction;\ng(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function after instanceof on a hashbang line", map[string]string{"app.js": "#! node instanceof\nFunction == 0;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function compared after a member named instanceof", map[string]string{"app.js": "const o = {};\nObject.prototype.valueOf = function () { if (this.name === 'Function') this(process.argv[2])(); return 0; };\no.instanceof\nFunction == 0;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function compared after a member named instanceof and a carriage return", map[string]string{"app.js": "const o = {};\nObject.prototype.valueOf = function () { if (this.name === 'Function') this(process.argv[2])(); return 0; };\no.instanceof\rFunction == 0;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function compared after a member named instanceof and a line separator", map[string]string{"app.js": "const o = {};\nObject.prototype.valueOf = function () { if (this.name === 'Function') this(process.argv[2])(); return 0; };\no.instanceof\u2028Function == 0;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function compared after a member named instanceof and a paragraph separator", map[string]string{"app.js": "const o = {};\nObject.prototype.valueOf = function () { if (this.name === 'Function') this(process.argv[2])(); return 0; };\no.instanceof\u2029Function == 0;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function compared after a member named instanceof and a comment holding a carriage return", map[string]string{"app.js": "const o = {};\nObject.prototype.valueOf = function () { if (this.name === 'Function') this(process.argv[2])(); return 0; };\no.instanceof /*\r*/ Function == 0;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function compared after a member named instanceof and a comment holding a line separator", map[string]string{"app.js": "const o = {};\nObject.prototype.valueOf = function () { if (this.name === 'Function') this(process.argv[2])(); return 0; };\no.instanceof /*\u2028*/ Function == 0;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function compared after a member named instanceof and a comment holding a paragraph separator", map[string]string{"app.js": "const o = {};\nObject.prototype.valueOf = function () { if (this.name === 'Function') this(process.argv[2])(); return 0; };\no.instanceof /*\u2029*/ Function == 0;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol assigned after a member named typeof and a comment holding a line separator", map[string]string{"app.js": "const cfg = {};\nconst t = cfg.typeof /*\u2028*/ Symbol = { hasInstance: 'constructor' };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function compared after a private name instanceof", map[string]string{"app.js": "Object.prototype.valueOf = function () { if (this.name === 'Function') this(process.argv[2])(); return 0; };\nclass A { #instanceof = 0; m() { this.#instanceof\nFunction == 0 } }\nnew A().m();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function compared after a number's instanceof", map[string]string{"app.js": "Object.prototype.valueOf = function () { if (this.name === 'Function') this(process.argv[2])(); return 0; };\n1..instanceof\nFunction != 0;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read through a dotted namespace named Symbol", map[string]string{"app.js": "namespace Symbol.hasInstance { export function toString() { return 'constructor'; } }\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read through a dotted module named Symbol", map[string]string{"app.js": "module Symbol.hasInstance { export function toString() { return 'constructor'; } }\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol assigned after a private name typeof", map[string]string{"app.js": "class A { #typeof = 0; m() { this.#typeof\nSymbol = { hasInstance: 'constructor' }; } }\nnew A().m();\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol assigned after a number's typeof", map[string]string{"app.js": "const t = 1..typeof\nSymbol = { hasInstance: 'constructor' };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read inside a dotted namespace naming Symbol", map[string]string{"app.ts": "namespace A.Symbol.hasInstance {\n  export function toString() { return 'constructor'; }\n  var h = Function.prototype[Symbol.hasInstance];\n  h(process.argv[2])();\n}" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read inside a module dotted twice before Symbol", map[string]string{"app.ts": "module A.B.Symbol.hasInstance {\n  export function toString() { return 'constructor'; }\n  var h = Function.prototype[Symbol.hasInstance];\n  h(process.argv[2])();\n}" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after an HTML open comment holding a quote", map[string]string{"app.js": "<!-- don't\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after an HTML close comment holding a quote", map[string]string{"app.js": "var x = 1;\n--> don't\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a regex read as division after an if", map[string]string{"app.js": "if (true) /'/;\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a regex read as division after return", map[string]string{"app.js": "function q(s) { return /'/.test(s) }\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a regex read as division after a block", map[string]string{"app.js": "{}\n/'/;\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a regex holding a comment opener", map[string]string{"app.js": "function q(s) { return /[/*]/.test(s) }\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // */\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a regex holding a line comment opener", map[string]string{"app.js": "function q(s) { return /[//]/.test(s) }; var Symbol = { hasInstance: { toString: function () { return \"constructor\" } } };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"function binder for Symbol hidden by a regex read as division", map[string]string{"app.js": "function q(s) { return /'/.test(s) }\nfunction //'\nSymbol() {}\nSymbol.hasInstance = { toString: function () { return \"constructor\" } };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared between divisions read as a regex after a postfix increment", map[string]string{"app.js": "var a = 0, y = 1;\na++ / 2; var Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; y / 1;\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared between divisions read as a regex after a postfix decrement", map[string]string{"app.js": "var a = 0, y = 1;\na-- / 2; var Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; y / 1;\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared between divisions read as a regex after a non-null assertion", map[string]string{"app.ts": "var a: any = 0, y = 1;\na! / 2; var Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; y / 1;\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared between divisions read as a regex after type arguments", map[string]string{"app.ts": "var a: any = 0, y = 1;\nvar z = a as Array<number> / 2; var Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; y / 1;\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function compared after a member named instanceof and a comment holding a line feed", map[string]string{"app.js": "const o = {};\nObject.prototype.valueOf = function () { if (this.name === 'Function') this(process.argv[2])(); return 0; };\no.instanceof /*\n*/ Function == 0;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol assigned after a member named typeof and a comment holding a line feed", map[string]string{"app.js": "const cfg = {};\nconst t = cfg.typeof /*\n*/ Symbol = { hasInstance: 'constructor' };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared between a regex and a division read as a second regex", map[string]string{"app.js": "var r = /a/ / 2; var Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; var y = r / 1;\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a regex starting a line after a declaration", map[string]string{"app.js": "var a\n/'/.test(\"x\");\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a regex starting a line after break", map[string]string{"app.js": "for (;;) { break\n/'/\n}\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a regex starting a line after an import", map[string]string{"app.js": "import \"node:fs\"\n/'/.test(\"x\");\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a regex starting a line after a type annotation", map[string]string{"app.ts": "let a: number\n/'/.test(\"x\");\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared between divisions read as a regex after a doubled non-null assertion", map[string]string{"app.ts": "var a: any = 0, y = 1;\na!! / 2; var Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; y / 1;\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared between divisions read as a regex after a non-null object literal", map[string]string{"app.ts": "var y = 1;\nvar a = {}! / 2; var Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; y / 1;\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a template whose substitution holds an object literal", map[string]string{"app.js": "var t = `${ {}.a || `'` }`;\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a template whose substitution holds a block", map[string]string{"app.js": "var t = `${ [1].map(x => { return x }) + `'` }`;\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after JSX text holding an apostrophe", map[string]string{"app.jsx": "const e = <p>don't</p>;\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after TSX text holding an apostrophe", map[string]string{"app.tsx": "const e = <p>don't</p>;\nvar Symbol = { hasInstance: { toString: function () { return \"constructor\" } } }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared after a JSX attribute ending in a backslash", map[string]string{"app.jsx": "const e = <p a=\"\\\" />;\nvar Symbol = { hasInstance: { toString: function () { return 'constructor' } } }; // \"\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"function named Symbol after a byte order mark", map[string]string{"app.js": "function\uFEFFSymbol() {}\nSymbol.hasInstance = { toString: function () { return \"constructor\" } };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read through a namespace named Symbol after a byte order mark", map[string]string{"app.ts": "namespace\uFEFFSymbol.hasInstance { export function toString() { return 'constructor'; } }\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read inside a dotted namespace with a byte order mark before Symbol", map[string]string{"app.ts": "namespace A.\uFEFFSymbol.hasInstance {\n  export function toString() { return 'constructor'; }\n  var h = Function.prototype[Symbol.hasInstance];\n  h(process.argv[2])();\n}" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read inside a dotted namespace with a byte order mark before the dot", map[string]string{"app.ts": "namespace A\uFEFF.Symbol.hasInstance {\n  export function toString() { return 'constructor'; }\n  var h = Function.prototype[Symbol.hasInstance];\n  h(process.argv[2])();\n}" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read inside a dotted namespace whose keyword a regex hides", map[string]string{"app.ts": "function q(s) { return /'/.test(s) }\nnamespace //'\nA.Symbol.hasInstance {\n  export function toString() { return 'constructor'; }\n  var h = Function.prototype[Symbol.hasInstance];\n  h(process.argv[2])();\n}" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read in a with statement a regex hides", map[string]string{"app.js": "var o = JSON.parse(process.argv[3]);\nif (true) /'/; with (o) //'\n{ var h = Function.prototype[Symbol.hasInstance]; h(process.argv[2])(); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read in a with statement a regex hides before a comment", map[string]string{"app.js": "var o = JSON.parse(process.argv[3]);\nif (true) /'/; with /**/ (o) //'\n{ var h = Function.prototype[Symbol.hasInstance]; h(process.argv[2])(); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol assigned past a line comment ended by a line separator", map[string]string{"app.js": "Symbol // c\u2028= { x: { hasInstance: 'constructor' } }\n.x;\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"escaped Symbol declared in code a regex read as division hides after a Symbol", map[string]string{"app.js": "if (true) /[ Symbol //]/; var \\u0053ymbol = { x: { hasInstance: 'constructor' } }\n.x;\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"escaped Symbol declared in code an HTML-like open comment holding a quote hides", map[string]string{"app.js": "x <!-- don't\nvar \\u0053ymbol = { x: { hasInstance: \"constructor\" } }.x; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"escaped Symbol declared in code an HTML-like close comment holding a quote hides", map[string]string{"app.js": "var a = 1;\n--> don't\nvar \\u0053ymbol = { x: { hasInstance: \"constructor\" } }.x; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"escaped Symbol declared in text the blanked copy hides", map[string]string{"app.js": "var a\n/'/.test(\"x\");\nvar \\u0053ymbol = { hasInstance: \"constructor\" }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared with a braced escape in text the blanked copy hides", map[string]string{"app.js": "var a\n/'/.test(\"x\");\nvar \\u{53}ymbol = { hasInstance: \"constructor\" }; // '\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"with hidden by the blanked copy before an HTML-like open comment", map[string]string{"app.js": "var o = JSON.parse(process.argv[3]);\nvar a\n/'/.test(\"x\");\nwith <!-- '\n(o) { var h = Function.prototype[Symbol.hasInstance]; h(process.argv[2])(); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"with hidden by the blanked copy before an HTML-like close comment", map[string]string{"app.js": "var o = JSON.parse(process.argv[3]);\nvar a\n/'/.test(\"x\");\nwith\n--> '\n(o) { var h = Function.prototype[Symbol.hasInstance]; h(process.argv[2])(); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance read inside a dotted namespace whose keyword is escaped", map[string]string{"app.ts": "n\\u0061mespace A.Symbol.hasInstance {\n  export function toString() { return 'constructor'; }\n  var h = Function.prototype[Symbol.hasInstance];\n  h(process.argv[2])();\n}" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"function named Symbol past an HTML-like open comment", map[string]string{"app.js": "function <!--\nSymbol() {}\nSymbol.hasInstance = { toString: function () { return \"constructor\" } };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"function named Symbol past an HTML-like close comment", map[string]string{"app.js": "function\n--> c\nSymbol() {}\nSymbol.hasInstance = { toString: function () { return \"constructor\" } };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"global Symbol replaced in code a regex read as division hides after a Symbol", map[string]string{"app.js": "if (true) /[ Symbol //]/; globalThis['Sym' + 'bol'] = { x: { hasInstance: 'constructor' } }\n.x;\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype beside Symbol.hasInstance in an array", map[string]string{"app.js": "const a = [Function.prototype, Symbol.hasInstance];\na[0].constructor(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function.prototype indexed by another object's hasInstance", map[string]string{"app.js": "const o = { hasInstance: 'constructor' };\nFunction.prototype[o.hasInstance](process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function as instanceof's operand called with type arguments", map[string]string{"app.js": "function f(x: unknown) { return x instanceof Function<any>(process.argv[2])(); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function as instanceof's operand tagging a template with type arguments", map[string]string{"app.js": "function f(x: unknown) { return x instanceof Function<any>`x`; }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function as instanceof's operand before an HTML open comment", map[string]string{"app.js": "function f(x) { return x instanceof Function <!-- c\n(process.argv[2])(); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function as instanceof's operand before an HTML close comment", map[string]string{"app.js": "function f(x) { return x instanceof Function\n--> c\n(process.argv[2])(); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function as instanceof's operand before a single ampersand", map[string]string{"app.js": "function f(x) { return x instanceof Function & 1; }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function as instanceof's operand before an assignment", map[string]string{"app.js": "function f(x) { return x instanceof Function = process.argv[2]; }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function as instanceof's operand before an optional call", map[string]string{"app.js": "function f(x) { return x instanceof Function?.(process.argv[2])(); }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance builtin before an HTML open comment", map[string]string{"app.js": "var h = Function.prototype[Symbol.hasInstance] <!-- c\n.constructor(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"hasInstance builtin before a line break", map[string]string{"app.js": "var h = Function.prototype[Symbol.hasInstance]\n.constructor(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol assigned after a member named typeof", map[string]string{"app.js": "const cfg = {};\nconst t = cfg.typeof\nSymbol = { hasInstance: 'constructor' };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol assigned after typeof in an HTML open comment", map[string]string{"app.js": "var <!-- typeof\nSymbol = { hasInstance: 'constructor' };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol assigned after typeof in an HTML close comment", map[string]string{"app.js": "var x = 1\n--> typeof\nSymbol = { hasInstance: 'constructor' };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Symbol declared with an escape", map[string]string{"app.js": "var \\u0053ymbol = { hasInstance: 'constructor' };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"global Symbol replaced by a member write", map[string]string{"app.js": "globalThis.Symbol = { hasInstance: 'constructor' };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"global Symbol replaced by a literal key", map[string]string{"app.js": "globalThis['Symbol'] = { hasInstance: 'constructor' };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"global Symbol replaced through parentheses", map[string]string{"app.js": "(Symbol) = { hasInstance: 'constructor' };\nvar h = Function.prototype[Symbol.hasInstance];\nh(process.argv[2])();" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"global root from Function", map[string]string{"app.js": "var root = Function('return this')() || {};" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"global from Function read by a literal member", map[string]string{"app.js": "const T = Function('return this')().TextEncoder;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function as an optional parameter type", map[string]string{"app.js": "function run(cb?: Function, f?: Function): Function | undefined { return cb; }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function as a parameter type after a ternary default", map[string]string{"app.js": "function run(a = process.env.X ? 1 : 2, cb: Function) { return cb; }" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"Function as a type after a nullish default", map[string]string{"app.js": "const v = process.env.X ?? 'y'\nlet cb: Function;" + "\nfunction load(s) { return s; }\nload(process.argv);\n"}, plugin.PartialReasonEvaluatedCode},
		{"a call of Function.call stored on Function", map[string]string{"app.js": `
Function.foo = Function.call; Function.foo(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a call of Function.call stored on Function across a line", map[string]string{"app.js": `
Function.foo = Function.call
Function.foo(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a call of Function.bind stored on Function", map[string]string{"app.js": `
Function.foo = Function.bind; Function.foo(null, process.argv[2])()();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a call of Function.apply stored on Function", map[string]string{"app.js": `
Function.foo = Function.apply; Function.foo(null, [process.argv[2]])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a call of Function.call stored on Function through an operator", map[string]string{"app.js": `
Function.foo = Function.call || 0; Function.foo(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a call of Function.call stored on Function.prototype", map[string]string{"app.js": `
Function.prototype.foo = Function.call; Function.foo(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a call of Function.call stored on Object.prototype", map[string]string{"app.js": `
Object.prototype.foo = Function.call; Function.foo(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a call of Function.call stored on Function.__proto__", map[string]string{"app.js": `
Function.__proto__.foo = Function.call; Function.foo(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a call of Function.call defined on Function.prototype", map[string]string{"app.js": `
Object.defineProperty(Function.prototype, 'foo', {value: Function.call}); Function.foo(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a call of Function.call stored by a destructuring default", map[string]string{"app.js": `
({foo: Function.foo = Function.call} = {}); Function.foo(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call spelled with an escape after its first letter", map[string]string{"app.js": `
Function.c\u0061ll(null, process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.bind spelled with an escape after its first letter", map[string]string{"app.js": `
Function.b\u0069nd(null, process.argv[2])()();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.constructor spelled with an escape at its end", map[string]string{"app.js": `
Function.constructo\u0072(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.call tagged with no space", map[string]string{"app.js": `
Function.call` + "`" + `${'a'}${process.argv[2]}` + "`" + `();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function.apply tagged with no space", map[string]string{"app.js": `
Function.apply` + "`" + `${[process.argv[2]]}` + "`" + `();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a literal Function called at once", map[string]string{"app.js": `
const one = Function('return 1')();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"a literal Function called optionally at once", map[string]string{"app.js": `
const one = Function('return 1')?.();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function called optionally on any receiver", map[string]string{"app.js": `
function run(o) { return o.Function?.(process.argv[2])(); }
module.exports = run;
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function handed on beside a literal argument", map[string]string{"app.js": `
function call(F, s) { return F(process.argv[2])(); }
call(Function, 'return 1');
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"literal Function reading a name the scan cannot spell", map[string]string{"app.js": `
const k = 'ev' + 'al';
Ⅰ = globalThis;
const g = Function('return Ⅰ');
setTimeout(() => g()[k](process.argv[2]));
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function after a member named import", map[string]string{"app.js": `
var cfg = {};
cfg.import, Function(process.argv[2])();
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"Function in a block after a member named export", map[string]string{"app.js": `
var cfg = {};
cfg?.export
{ Function(process.argv[2])(); }
function load(s) { return s; }
load(process.argv);
`}, plugin.PartialReasonEvaluatedCode},
		{"literal Function reading a parameter name joined to a ZWNJ", map[string]string{"app.js": `
const k = 'ev' + 'al';
x‌ = globalThis;
const g = Function('x', 'return x‌');
g()[k](process.argv[2]);
function load(s) { return s; }
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
		"fmt.ts":       "export function fmt(s: string, cb?: () => void) { return s; }\n",
		"config.json":  `{"a": 1}`,
		"package.json": `{"name": "app", "imports": {"#u": {"import": "./util.js", "require": "./util.js", "types": "./util.d.ts"}}}`,
		"app.js": `
const { trim } = require('./util');
import './util';
import { fmt } from './fmt.js';
const u = require('#u');
const cfg = require('./config.json');
const where = require.resolve('./util');
if (typeof require === 'function' && cfg.eval === true) { load(where); }
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
// parameter or function named require, a test of a loader, and Function consumed as
// instanceof's operand or by a Function.prototype builtin load nothing this lane does not read.
func TestCallGraph_LoaderShapesThatHandNothingOn(t *testing.T) {
	cases := []struct{ name, app string }{

		// C1
		{"dispatch table indexed by a safe literal", "const table = { run: s => s }; table['run']('x');"},

		// C2
		{"scoped dispatch table indexed by data", "function dispatch(k) { const table = { run: s => s }; return table[k]('x'); } dispatch(process.argv[4]);"},

		// C3
		{"top-level const dispatch table indexed by data", "const table = { run: s => s }; table[process.argv[4]]('x');"},

		// C3-private
		{"top-level const dispatch table beside an updated private field of its name", "const table = { run: s => s }; class A { #table; m() { this.#table++; } } table[process.argv[4]]('x');"},

		// R3C1
		{"Object indexed by a const naming keys", "const table = { run: s => s }; const m = 'keys'; Object[m](table).length; table[process.argv[4]]('x');"},

		// R3C2
		{"Reflect indexed by a concatenation naming has", "const table = { run: s => s }; Reflect['h' + 'as'](table, 'run'); table[process.argv[4]]('x');"},

		// R3C3
		{"var receiver beside a same-named function declared in a nested function", "function run(k) { var o = { a: s => s }; function h() { { function o() {} } } return o[k]('x'); } run(process.argv[4]);"},

		// R3C4
		{"Object and Reflect only tested", "const table = { run: s => s }; if (table instanceof Object && typeof Reflect === 'object' && table.constructor === Object) { table[process.argv[4]]('x'); }"},

		// C5
		{"function array indexed by a numeric counter", "const table = [s => s]; for (let i = 0; i < table.length; i++) table[i]('x');"},

		// C6-arithmetic
		{"function indexed by a arithmetic key", "function g() {} g[process.argv[4] - 1]('x');"},

		// C6-unary
		{"function indexed by a unary key", "function g() {} g[+process.argv[4]]('x');"},

		// C6-numeric
		{"function indexed by a numeric key", "function g() {} g[0]('x');"},

		// C7-concat
		{"function indexed by a digit-ending concat", "function g() {} g[process.argv[4] + 1]('x');"},

		// C7-template
		{"function indexed by a digit-ending template", "function g() {} g[`${process.argv[4]}1`]('x');"},

		// C8-concat
		{"function indexed by an impossible concat key", "function g() {} g['_' + process.argv[4]]('x');"},

		// C8-template
		{"function indexed by an impossible template key", "function g() {} g[`X${process.argv[4]}`]('x');"},

		// C9-for-of
		{"safe literal iteration through for-of", "function g() {} for (const k of ['name', 'length']) { g[k]('x'); }"},

		// C9-foreach
		{"safe literal iteration through foreach", "function g() {} ['name', 'length'].forEach(k => g[k]('x'));"},

		// C10-for-in
		{"same receiver own enumeration through for-in", "const r = { run: s => s }; for (const k in r) { r[k]('x'); }"},

		// C10-keys
		{"same receiver own enumeration through keys", "const r = { run: s => s }; for (const k of Object.keys(r)) { r[k]('x'); }"},

		// C10-entries
		{"same receiver own enumeration through entries", "const r = { run: s => s }; for (const [k, value] of Object.entries(r)) { r[k]('x'); }"},

		// C11-includes
		{"constructor deny list searched with includes", "const k = process.argv[4]; if (['constructor'].includes(k)) load('x');"},

		// C11-indexOf
		{"constructor deny list searched with indexOf", "const k = process.argv[4]; if (['constructor'].indexOf(k)) load('x');"},

		// C11-some
		{"constructor deny list searched with some", "const k = process.argv[4]; if (['constructor'].some(x => x === k)) load('x');"},

		// C12-compare
		{"data keyed function member only used as compare", "function g() {}\nconst k = process.argv[4];\nif (g[k] === null) load(\"x\");"},

		// C12-typeof
		{"data keyed function member only used as typeof", "function g() {}\nconst k = process.argv[4];\nif (typeof g[k] === \"function\") load(\"x\");"},

		// C12-assign
		{"data keyed function member only used as assign", "function g() {}\nconst k = process.argv[4];\ng[k] = 1;"},

		// C12-arithmetic
		{"data keyed function member only used as arithmetic", "function g() {}\nconst k = process.argv[4];\nconst n = g[k] - 1;"},

		// C12-member
		{"data keyed function member only used as member", "function g() {}\nconst k = process.argv[4];\nconst n = g[k].name;"},

		// C12-alias
		{"data keyed function member only used as alias", "function g() {}\nconst k = process.argv[4];\nconst F = g[k]; if (typeof F === \"function\" && F.name !== \"\") load(\"x\");"},

		// C13
		{"numeric matrix read written and compared", "const grid = [[0]]; let n = 0; for (let i = 0; i < 1; i++) { grid[i][0] = grid[i][n] + 1; n += grid[n][i]; if (grid[i][n] === 0) n--; }"},

		// C14
		{"Reflect get with a safe literal", "function g() {} const name = Reflect.get(g, 'name');"},

		// C15-member
		{"descriptors result only used as member", "function g() {} const n = Object.getOwnPropertyDescriptors(g).name;"},

		// C15-in
		{"descriptors result only used as in", "function g() {} if ('name' in Object.getOwnPropertyDescriptors(g)) load('x');"},

		// C15-hasOwnProperty
		{"descriptors result only used as hasOwnProperty", "function g() {} if (Object.getOwnPropertyDescriptors(g).hasOwnProperty('name')) load('x');"},

		// C-key-const
		{"safe keys propagated through const", "function g() {} const key = 'name'; g[key]('x');"},

		// C-key-ternary
		{"safe keys propagated through ternary", "function g() {} const key = process.argv[5] ? 'name' : 'length'; g[key]('x');"},

		// C-key-or
		{"safe keys propagated through or", "function g() {} const key = 'name' || 'length'; g[key]('x');"},

		// C-key-nullish
		{"safe keys propagated through nullish", "function g() {} const key = 'name' ?? 'length'; g[key]('x');"},
		{"browserify module wrapper", "var mods = {1: [function (require, module, exports) { module.exports = require('./util'); }, {}]};"},
		{"this indexed in generator methods", "class C { *items(k) { yield typeof this[k]; } }\nconst o = { *gen(k) { yield typeof this[k]; } };\nmodule.exports = { C, o };"},
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
		{"global member read", "const enc = globalThis.TextEncoder;"},
		{"imported names of global names", "import { top, left } from './util';\nimport * as parent from './util';\nimport self from './util';\nexport const placements = [top, left, parent, self];"},
		{"global name as an arrow parameter", "const isSuper = (node, parent) => isClass(parent) && parent.superClass === node;\nfunction isClass(n) { return !!n; }"},
		{"global name as a parameter of a multi-line arrow", "const isMember = (node, parent) =>\n  isA(parent) ||\n  isB(parent);\nfunction isA(n) { return !!n; }\nfunction isB(n) { return !n; }"},
		{"global name as an index key", "function pad(col) { return col.padding[top] | 0; }"},
		{"parent as a local", "function walk(node, k) { const parent = node.parent; return typeof parent[k]; }"},
		{"top as a parameter", "function peek(top, k) { return typeof top[k]; }"},
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
		{"Function as instanceof's operand", "function isFn(x) { return x instanceof Function && typeof x === 'function'; }"},
		{"Function as instanceof's operand at the end of a statement", "function isFn(x) { return x instanceof Function }"},
		{"Function.prototype.apply called through call", "function log() { return Function.prototype.apply.call(console.log, console, arguments); }"},
		{"Function.prototype.toString called through call", "const src = Function.prototype.toString.call(trim);"},
		{"Function.prototype.call bound", "const has = Function.prototype.call.bind(Object.prototype.hasOwnProperty);"},
		{"Function.prototype.bind called", "const noop = Function.prototype.bind(null);"},
		{"hasInstance builtin stored", "var realHasInstance;\nif (typeof Symbol === 'function' && Symbol.hasInstance && typeof Function.prototype[Symbol.hasInstance] === 'function') {\n  realHasInstance = Function.prototype[Symbol.hasInstance];\n  Object.defineProperty(trim, Symbol.hasInstance, { value: function (o) { return realHasInstance.call(this, o); } });\n}"},
		{"hasInstance builtin called through call", "const is = Function.prototype[Symbol.hasInstance].call(trim, {});"},
		{"hasInstance builtin called", "const is = Function.prototype[Symbol.hasInstance](trim);"},
		{"Symbol method shorthand named Symbol beside hasInstance", "const o = { Symbol() { return Symbol('x'); } };\nvar h = Function.prototype[Symbol.hasInstance];"},
		{"Function as instanceof's operand ending each kind of operand", "function isFn(x, y) { return [x instanceof Function, (y instanceof Function), x instanceof Function ? 1 : 0, y ? x instanceof Function : 0, { a: x instanceof Function }, x instanceof Function || y, x instanceof Function ?? y, x instanceof Function == y, x instanceof Function != y]; }"},
		{"a member Symbol read beside hasInstance", "const s = globalThis.Symbol.for('x');\nvar h = Function.prototype[Symbol.hasInstance];"},
		{"hasInstance builtin beside regexes after an arrow, a negation and a paren", "const ok = (s) => /^x/.test(s) && !/y/.test(s) && (/z/).test(s);\nfunction t(s) { return !/w/.test(s); }\nvar h = Function.prototype[Symbol.hasInstance];"},
		{"hasInstance builtin beside divisions after names, members named as keywords and brackets", "let i = 0;\nconst r = a / 2 + b[0] / 3 + 'x'.length / 4 + cfg.default / 5;\ni++ // count\nvar h = Function.prototype[Symbol.hasInstance];"},
		{"hasInstance builtin beside prose naming with", "// works with any input\nvar h = Function.prototype[Symbol.hasInstance];"},
		{"hasInstance builtin stored in a ternary", "var h = process.env.X ? Function.prototype[Symbol.hasInstance] : null;"},
		{"Function of parameters", "const add = new Function('a', 'b', 'return a + b');"},
		{"Function of a parameter list", "const min = Function('a, b', 'return a < b ? a : b');"},
		{"Function with an empty body", "const noop = Function('');"},
		{"Function of nothing", "const nil = Function();"},
		{"a member named Function tested on a parameter", "function hasCtor(o) { return o.Function !== undefined; }"},
		{"a literal Function stored and called later", "const add = Function('a', 'b', 'return a + b');\nconst three = add(1, 2);"},
		{"Function body with a string", "const tag = Function('a', 'return a == \"x\" ? 1 : 0');"},
		{"global require tested", "const electron = typeof window !== 'undefined' && !!(window.require && window.process);"},
		{"require property of a plain object", "const opts = { a: 1 };\nconst r = opts.require;\nmodule.exports = cfg.loader.require;"},
		{"require and module as object keys", "module.exports = { require: ['./util'], module: { rules: [] } };"},
		{"UMD export guard", "var X = {};\nif (typeof module !== 'undefined' && module.exports) { module.exports = X; } else { this.X = X; }"},
		{"lodash freeModule", "var freeExports = typeof exports == 'object' && exports;\nvar freeModule = freeExports && typeof module == 'object' && module && !module.nodeType && module;\nvar moduleExports = freeModule && freeModule.exports === freeExports;"},
		{"process members and destructuring", "const dev = process.env.NODE_ENV !== 'production';\nprocess.on('exit', () => {});\nconst { env, argv } = process;\nconst p = typeof process !== 'undefined' ? process.env : {};"},
		{"module data members", "if (module.hot) { module.hot.accept(); }\nmodule.exports = { id: module.id, file: module['filename'] };"},
		{"module re-exported under its name", "const m = 1;\nexport { m as module };"},
		{"constructor of a value, of this and of a class read, tested and assigned", "class Box { constructor(v) { this.v = v; } clone() { return new this.constructor(); } }\nconst b = new Box(1);\nfunction Sub() {}\nSub.prototype.constructor = Sub;\nconst isBuf = b.constructor != null && typeof b.constructor.isBuffer === 'function';\nmodule.exports = { same: b.constructor === Box, name: b?.constructor.name, own: b instanceof b.constructor, plain: Object.getPrototypeOf(b).constructor !== Object, isBuf };"},
		{"a two-dimensional array read, written, compared and iterated", "const grid = [[0]];\nlet total = 0;\nfor (let i = 0; i < 1; i++) for (let j = 0; j < 1; j++) { grid[i][j] = grid[i][j] + 1; total += grid[i][j]; if (grid[i][j] === 0) total--; grid[i][j]++; total = -grid[i][j] * 2; for (const c of grid[i][j]) total += c; }\nmodule.exports = { total, n: grid[0][0], len: grid[total][0].length };"},
		{"property named module on a plain object", "const cfg = {};\ncfg.module = 1;\nmodule.exports = cfg.module.rules;"},
		{"global alias guarded by tests", "var freeGlobal = typeof global == 'object' && global && global.Object === Object && global;\nvar root = freeGlobal || {};"},
		{"top-level this tested", "var __extends = (this && this.__extends) || function (d, b) { d.prototype = b; };"},
		{"TypeScript function return type", "function pick(this: Box, k: string): Box { const s = wrap(this); return s; }\nfunction wrap(o) { return o; }"},
		{"self declared from this", "function Stream(k, fn) { var self = this; fn.call(self, k); return typeof self[k]; }"},
		{"self as a parameter", "function bind(self, fn) { return fn.apply(self, arguments); }"},
		{"self as an arrow parameter", "const call = (self, k) => { return typeof self[k]; };"},
		{"global as a block-scoped local", "function walk(node) { let global = node.scope; return typeof global[node.name]; }"},
		{"window declared from a parameter", "function setup(win) { const window = win; return typeof window[win.key]; }"},
		{"self declared in a nested function", "function outer(o) { return function inner() { var self = o; return typeof self[o.k]; }; }"},
		{"this handed on in a plain function", "function wrap(fn) { return function () { return fn.apply(this, arguments); }; }"},
		{"this aliased in a plain function", "function Box(k) { var that = this; that[k] = 1; return that; }"},
		{"this indexed without a call in a plain function", "function Box(k) { this[k] = 1; }"},
		{"global literal key", "const enc = globalThis['TextEncoder'];"},
		{"global probed", "const hasWin = typeof window !== 'undefined' && window === self;"},
		{"this indexed in a method", "const o = { pick(k) { return typeof this[k]; } };"},
		{"this indexed in a class method", "class Box { pick(k) { return typeof this[k]; } }"},
		{"this indexed in an arrow inside a method", "class Box { pick(k) { const f = () => typeof this[k]; return f(); } }"},
		{"this indexed in a getter", "const o = { get v() { return this['_' + 'v']; } };"},
		{"this indexed in a constructor", "class Box { constructor(k) { typeof this[k]; } }"},
		{"global name bound by a for-of header, indexed in the body", "for (const self of [load]) { typeof self[process.argv[2]]; }\nfunction load(s) { return s; }"},
		{"global name bound by a for header, indexed in the body", "for (let top = {}; top; top = null) { top[process.argv[2]](1); }"},
		{"global name bound by a for await header, indexed in the body", "async function run(xs) { for await (const parent of xs) { typeof parent[process.argv[2]]; } }"},
		{"a value import beside an inline type import", "import self, { type T } from './util';\ntypeof self[process.argv[2]];"},
		{"an import named type", "import type from './util';\nimport { type as t } from './util';\ntypeof type[process.argv[2]] === t;"},
		{"a method's this in a TypeScript generic class implementing two interfaces", "class A<T, R> extends Array<R> implements I, J { m(): T { return typeof this[process.argv[2]]; } }"},
		{"global name declared by a TypeScript namespace var, indexed inside it", "namespace N { var self = { a: 1 }; self[process.argv[2]](1); }"},
		{"global name as an arrow parameter in a ternary branch", "const f = process.env.X ? window => typeof window[process.argv[2]] : null;"},
		{"an arrow body holding a whole ternary", "const f = window => window ? typeof window[process.argv[2]] : 0;"},
		{"global name as an arrow parameter used in its own ternary else", "const c = process.env.X;\nconst f = window => c ? 0 : typeof window[process.argv[2]];"},
		{"the global assigned to an undeclared global name", "let x = 1;\nself = globalThis;\nconsole.log(self.location, x);"},
		{"members compared with globals and a compound assignment", "const o = {};\nif (o.g === globalThis || o.h !== window || o.i >= self || o.j <= top) {}\nlet n = 0;\nn += self;"},
		{"a member compared with a global", "const o = {};\nif (o.g == globalThis) { o.g = 1; }"},
		{"a constructor returning this, constructed", "function G() { if (!(this instanceof G)) return new G(); return this; }\nvar g = new G(); trim(g);"},
		{"a function returning this, declared after a require with no semicolon", "var isAbsolute = require('./util').trim\nfunction g (p) {\n}\nfunction G (p) {\n  if (p) return this\n}\nmodule.exports = function (p) {\n  if (isAbsolute(p)) { return p }\n}\n"},
		{"a function called in place returning a test of its this", "var isES5 = (function () { 'use strict'; return this === undefined; })();\ntrim(isES5);"},
		{"a method's this in a class extending a member named interface", "const Base = { interface: class {} };\nclass A extends Base.interface { m() { return typeof this[process.argv[2]]; } }\nnew A().m();"},
		{"a method's this in a class extending a called member", "function mk() { return { B: class {} }; }\nclass A extends mk().B { m() { return typeof this[process.argv[2]]; } }\nnew A().m();"},
		{"a global-named parameter of an object literal method", "const o = { m(self) { return typeof self[process.argv[2]]; } };\no.m({ a: trim });"},
		{"a global-named parameter of a class method", "class A { m(parent) { return typeof parent[process.argv[2]]; } }\nnew A().m({ a: trim });"},
		{"a global-named parameter of a method in an object passed as an argument", "Object.assign({}, { m(top) { return typeof top[process.argv[2]]; } });"},
		{"a function called in place with an object for its this", "(function () { var s = this; typeof s[process.argv[2]]; }).call({ a: trim });"},
		{"a TypeScript namespace var of a global name", "namespace N { var self = { a: 1 }; export const x = self[process.argv[2]]; }"},
		{"a dotted TypeScript namespace var of a global name", "namespace A.B { var self = { a: 1 }; export const x = self[process.argv[2]]; }"},
		{"a named generator's this, indexed", "function* g(k) { var t = this; yield typeof t[k]; }\nmodule.exports = g;"},
		{"a block-scoped let of a global name in a block after a parenthesised statement", "if (process.env.X) (0)\n{ let self = { a: 1 }; self[process.argv[2]](1); }"},
		{"an object literal method named catch", "var o = { catch(e) { var g = this; return typeof g[process.argv[2]]; } };\nmodule.exports = o;"},
		{"a function called in place returning a nested function's this", "var g = (function () { function h() { return this; } return h; })();\ntypeof g[process.argv[2]];"},
		{"a function called in place returning a member of its this", "var g = (function () { return this.x; })();\ntypeof g[process.argv[2]];"},
		{"a function returning an instanceof test of its this", "function F() { return this instanceof F; }\nvar g = F();\ntypeof g[process.argv[2]];"},
		{"an object literal method in a ternary's else after a call", "var o = process.env.X ? load(1) : { m() { var g = this; return typeof g[process.argv[2]]; } };\nmodule.exports = o;"},
		{"an import of a binding named type renamed to a global name", "import { type as self } from './util';\ntypeof self[process.argv[2]];"},
		{"a TypeScript namespace var of a global name, the brace on the next line", "namespace N\n{ var self; typeof self[process.argv[2]]; }"},
		{"a TypeScript namespace var of a global name, after a statement with no semicolon", "var a = 1\nnamespace M { var self; typeof self[process.argv[2]]; }"},
		{"a method's this in a class extending a call", "class Base {}\nclass A extends mixin(Base) { set(k, v) { this[k] = v; return this; } }\nfunction mixin(B) { return B; }"},
		{"a method's this in a class extending a parenthesised expression", "class Base {}\nclass A extends (process.env.X ? Base : Array) { chain() { return this; } }"},
		{"a method's this in a default-exported class extending a call", "class Base {}\nexport default class extends mixin(Base) { set(k, v) { this[k] = v; } }\nfunction mixin(B) { return B; }"},
		{"a method's this in a class extending a member call", "class A extends Base.extend({}) { set(k, v) { this[k] = v; } }"},
		{"a method's this in a class extending a call, inside a function", "class Base {}\nfunction f() { class A extends mixin(Base) { set(k, v) { this[k] = v; return this; } } return A; }\nfunction mixin(B) { return B; }"},
		{"a method's local of a global name in a class extending a call", "class Base {}\nclass A extends mixin(Base) { get(k) { const self = { a: 1 }; return self[k]; } }\nfunction mixin(B) { return B; }"},
		{"an object literal method after ||", "var store = process.env.X || { get(k) { return typeof this[k]; }, set(k, v) { this[k] = v; } };"},
		{"an object literal method after &&", "var o = process.env.X && { chain() { return this; } };"},
		{"an object literal method in a spread", "var o = { ...{ chain() { return this; } } };"},
		{"an object literal method after a keyword operator", "function* f() { yield { m(k) { return typeof this[k]; } }; }"},
		{"an object literal method after export default", "export default { m() { var g = this; return typeof g[process.argv[2]]; } };"},
		{"a member of a local of a global name named like the global", "const self = { self: { a: 1 } };\ntypeof self.self[process.argv[2]];"},
		{"a member named like the global on a property of the global", "globalThis.config = { self: { a: 1 } };\ntypeof globalThis.config.self[process.argv[2]];"},
		{"a block-level function of a global name, used in its block", "if (process.env.X) { function self(k) { return k; } typeof self[process.argv[2]]; }"},
		{"a member named like one global on a local of another", "const self = { window: { a: trim } };\nmodule.exports = typeof self.window[process.argv[2]];"},
		{"a TypeScript namespace import alias of a global name, used in the namespace", "namespace N { import self = Foo.bar; export const x = typeof self[process.argv[2]]; }"},
		{"a for header's let of a global name, used in the loop body", "for (let self = { a: trim }; process.env.X;) { self[process.argv[2]]; }"},
		{"an import of a global name after an underscore default import", "import _u, { self } from './util';\ntypeof self[process.argv[2]];"},
		{"an import of a global name after an underscore named import", "import { _b, self } from './util';\ntypeof self[process.argv[2]];"},
		{"an underscore-named import renamed to a global name", "import { _self as self } from './util';\ntypeof self[process.argv[2]];"},
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

// TestSymbolPlain_UnclosedBracedEscapesScanInLinearTime bounds the Symbol check's escape
// decoding: each unclosed \u{ ends at the first non-hex rune, so a run of them is not
// rescanned to the end of the module once per escape.
func TestSymbolPlain_UnclosedBracedEscapesScanInLinearTime(t *testing.T) {
	src := "var s = '" + strings.Repeat(`\u{`, 80000) + "';\nvar h = Function.prototype[Symbol.hasInstance];\n"
	clean := stripJS(src)
	start := time.Now()
	ok := symbolPlain([]rune(clean), []rune(src))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("symbolPlain took %v on 80000 unclosed \\u{ escapes; want under 1s", elapsed)
	}
	if !ok {
		t.Errorf("symbolPlain = false; want escapes in a string ignored")
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
