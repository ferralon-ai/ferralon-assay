package jsanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_ExportedLoaders: a loader that leaves its module can be called by any
// importer with any specifier, so exporting one declares a run-wide computed load.
func TestCallGraph_ExportedLoaders(t *testing.T) {
	const (
		uninspectable = plugin.PartialReasonUninspectablePackage
		computedReq   = plugin.PartialReasonComputedRequireSpecifier
	)
	cases := []struct {
		name    string
		files   map[string]string
		runWide []string
		absent  []string
	}{
		{
			name: "exported createRequire result escapes to importers",
			files: map[string]string{
				"u.mjs":   "export const req = module.constructor.createRequire(import.meta.url);\n",
				"app.mjs": "import { req } from './u.mjs';\nfunction load(s) { return req('json5').parse(s); }\nload(process.argv);\n",
			},
			runWide: []string{computedReq},
		},
		{
			name: "exported createRequire result from the module builtin",
			files: map[string]string{
				"u.mjs":   "import { createRequire } from 'module';\nexport const req = createRequire(import.meta.url);\n",
				"app.mjs": "import { req } from './u.mjs';\nfunction load(s) { return req('json5').parse(s); }\nload(process.argv);\n",
			},
			runWide: []string{computedReq},
		},
		{
			name: "createRequire result exported through an export list",
			files: map[string]string{
				"u.mjs":   "import { createRequire } from 'node:module';\nconst req = createRequire(import.meta.url);\nexport { req };\n",
				"app.mjs": "import { req } from './u.mjs';\nfunction load(s) { return req('json5').parse(s); }\nload(process.argv);\n",
			},
			runWide: []string{computedReq},
		},
		{
			name: "createRequire result exported through module.exports",
			files: map[string]string{
				"u.js":   "const req = module.constructor.createRequire(__filename);\nmodule.exports = { req };\n",
				"app.js": "const { req } = require('./u');\nfunction load(s) { return req('json5').parse(s); }\nload(process.argv);\n",
			},
			runWide: []string{computedReq},
		},
		{
			name: "require exported as a value",
			files: map[string]string{
				"u.js":   "exports.r = require;\n",
				"app.js": "const { r } = require('./u');\nfunction load(s) { return r('json5').parse(s); }\nload(process.argv);\n",
			},
			runWide: []string{computedReq},
		},
		{
			name: "unexported createRequire result called with a literal is a package load",
			files: map[string]string{
				"app.js": "const req = module.constructor.createRequire(__filename);\nfunction load(s) { return req('json5').parse(s); }\nload(process.argv);\n",
			},
			runWide: []string{uninspectable},
			absent:  []string{computedReq},
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
		})
	}
}
