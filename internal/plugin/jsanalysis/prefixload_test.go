package jsanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_StaticPrefixLoads pins how a load with a literal prefix and a runtime
// suffix is accounted for: real edges when every file the prefix names is an in-tree
// module, and in every case a run-wide limit, because the suffix may traverse out of the
// prefix (prefixSuffixMayTraverse). Nothing is scoped to a package.
func TestCallGraph_StaticPrefixLoads(t *testing.T) {
	const (
		uninspectable = plugin.PartialReasonUninspectablePackage
		computedReq   = plugin.PartialReasonComputedRequireSpecifier
		dynImport     = plugin.PartialReasonDynamicImportSpecifier
	)
	cases := []struct {
		name    string
		files   map[string]string
		runWide []string
		absent  []string
		edges   [][2]string // caller, callee
	}{
		{
			name:    "literal dynamic import is a package load, not a computed specifier",
			files:   map[string]string{"app.js": "async function f(s) { const J = await import('json5'); return J.parse(s); }\nf(process.argv);\n"},
			runWide: []string{uninspectable},
			absent:  []string{dynImport},
		},
		{
			name: "first-party prefix gets module-init edges",
			files: map[string]string{
				"plugins/a.js": "module.exports = 1;\n",
				"plugins/b.js": "module.exports = 2;\n",
				"app.js":       "function load(n) { return require('./plugins/' + n); }\nload(process.argv[2]);\n",
			},
			edges: [][2]string{
				{funcSCIP("app", nil, "load", 1), moduleInitSCIP("plugins/a")},
				{funcSCIP("app", nil, "load", 1), moduleInitSCIP("plugins/b")},
			},
			runWide: []string{computedReq},
		},
		{
			name: "top-level prefix load edges from the module frame",
			files: map[string]string{
				"plugins/a.js": "module.exports = 1;\n",
				"app.js":       "const p = require('./plugins/' + process.argv[2]);\n",
			},
			edges:   [][2]string{{moduleInitSCIP("app"), moduleInitSCIP("plugins/a")}},
			runWide: []string{computedReq},
		},
		{
			name: "prefix stem limits the enumeration",
			files: map[string]string{
				"plugins/p-a.js":   "module.exports = 1;\n",
				"plugins/other.js": "module.exports = 2;\n",
				"app.js":           "function load(n) { return require('./plugins/p-' + n); }\nload(process.argv[2]);\n",
			},
			edges:   [][2]string{{funcSCIP("app", nil, "load", 1), moduleInitSCIP("plugins/p-a")}},
			runWide: []string{computedReq},
		},
		{
			name: "template prefix gets module-init edges",
			files: map[string]string{
				"plugins/a.mjs": "export default 1;\n",
				"app.mjs":       "async function load(n) { return import(`./plugins/${n}`); }\nload(process.argv[2]);\n",
			},
			edges:   [][2]string{{funcSCIP("app", nil, "load", 1), moduleInitSCIP("plugins/a")}},
			runWide: []string{dynImport},
		},
		{
			name: "prefix over a node_modules dir stays run-wide without edges",
			files: map[string]string{
				"plugins/a.js":                        "module.exports = 1;\n",
				"plugins/node_modules/x/index.js":     "module.exports = 2;\n",
				"plugins/node_modules/x/package.json": `{"name":"x"}`,
				"app.js":                              "function load(n) { return require('./plugins/' + n); }\nload(process.argv[2]);\n",
			},
			runWide: []string{computedReq},
		},
		{
			name:    "prefix into a missing dir stays run-wide",
			files:   map[string]string{"app.js": "function load(n) { return require('./nope/' + n); }\nload(process.argv[2]);\n"},
			runWide: []string{computedReq},
		},
		{
			// 'lodash/' + '../json5' leaves lodash, so a package prefix bounds nothing.
			name:    "package prefix stays run-wide",
			files:   map[string]string{"app.js": "function load(n) { return require('lodash/' + n); }\nload(process.argv[2]);\n"},
			runWide: []string{computedReq},
		},
		{
			name:    "package template prefix stays run-wide",
			files:   map[string]string{"app.mjs": "async function load(n) { return import(`lodash/${n}`); }\nload(process.argv[2]);\n"},
			runWide: []string{dynImport},
		},
		{
			name:    "bare scope prefix stays run-wide",
			files:   map[string]string{"app.js": "function load(n) { return require('@babel/' + n); }\nload(process.argv[2]);\n"},
			runWide: []string{computedReq},
		},
		{
			name: "fully computed require stays run-wide (fixture C)",
			files: map[string]string{"index.js": `function add(a, b) {
  return a + b;
}
module.exports = { add };
function load(n) {
  return require(n);
}
`},
			runWide: []string{computedReq},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeProgram(t, tc.files)})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			p := res.Partiality
			if len(p.Scoped) != 0 {
				t.Errorf("want no scoped limits; got %+v", p.Scoped)
			}
			for _, r := range tc.runWide {
				if !hasReason(p, r) {
					t.Errorf("want run-wide %s; got reasons %v", r, p.Reasons)
				}
			}
			for _, r := range tc.absent {
				if hasReason(p, r) {
					t.Errorf("%s must be absent; got reasons %v", r, p.Reasons)
				}
			}
			for _, e := range tc.edges {
				if !hasEdge(res.Edges, e[0], e[1]) {
					t.Errorf("missing edge %s -> %s; got %+v", e[0], e[1], res.Edges)
				}
			}
			if len(tc.edges) == 0 {
				for _, e := range res.Edges {
					if e.Callee.SCIP == moduleInitSCIP("plugins/a") {
						t.Errorf("unexpected edge into an unenumerated prefix: %+v", e)
					}
				}
			}
		})
	}
}
