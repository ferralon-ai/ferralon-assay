package jsanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_VMStaysRunWide: vm runs source built at run time (runInThisContext,
// Script, compileFunction), so every way of reaching it keeps a run-wide limit.
func TestCallGraph_VMStaysRunWide(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"vm through require", map[string]string{"app.js": "const vm = require('vm');\nfunction f(s) { return vm.runInNewContext(s); }\nf(process.argv);\n"}},
		{"vm through a node: default import", map[string]string{"app.mjs": "import vm from 'node:vm';\nfunction f(s) { return vm.runInThisContext(s); }\nf(process.argv);\n"}},
		{"vm.Script through a named import", map[string]string{"app.mjs": "import { Script } from 'vm';\nfunction f(s) { return new Script(s).runInThisContext(); }\nf(process.argv);\n"}},
		{"vm.compileFunction through an inline require", map[string]string{"app.js": "function f(s) { return require('node:vm').compileFunction(s)(); }\nf(process.argv);\n"}},
		{"vm through a literal dynamic import", map[string]string{"app.js": "async function f(s) { const vm = await import('vm'); return vm.runInThisContext(s); }\nf(process.argv);\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeProgram(t, tc.files)})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if !hasReason(res.Partiality, plugin.PartialReasonUninspectablePackage) {
				t.Errorf("want run-wide %s; got reasons %v scoped %+v", plugin.PartialReasonUninspectablePackage, res.Partiality.Reasons, res.Partiality.Scoped)
			}
		})
	}
}
