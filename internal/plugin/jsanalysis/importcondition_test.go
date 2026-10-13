package jsanalysis

import (
	"context"
	"fmt"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_LiteralImportUnmodeledConditionKeepsLimit: a literal import() whose resolution
// passes through an exports/imports conditions map with a key outside loadConditions keeps
// the run-wide dynamic_import_specifier, because Node can select that branch
// (`node --conditions=development`) and loadsOutOfTree does not look at it. The controls
// resolve through maps with default keys only and declare no such limit.
func TestCallGraph_LiteralImportUnmodeledConditionKeepsLimit(t *testing.T) {
	const load = "async function load(s) { const m = await import('%s'); return m.parse(s); }\nload(process.argv);\n"
	workspace := `{"name":"root","workspaces":["packages/*"]%s}`
	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"#-subpath with a development branch to a package", map[string]string{
			"package.json":     `{"name":"app","imports":{"#cfg":{"development":"json5","default":"./plugins/index.js"}}}`,
			"plugins/index.js": "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js":           fmt.Sprintf(load, "#cfg"),
		}, true},
		{"#-subpath pattern with a custom condition", map[string]string{
			"package.json": `{"name":"app","imports":{"#p/*":{"edge-light":"./dist/*.js","default":"./src/*.js"}}}`,
			"src/a.js":     "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js":       fmt.Sprintf(load, "#p/a"),
		}, true},
		{"#-subpath mapped to a workspace member with a development export", map[string]string{
			"package.json":            fmt.Sprintf(workspace, `,"imports":{"#m":"m"}`),
			"packages/m/package.json": `{"name":"m","exports":{".":{"development":"./dev.js","default":"./src/index.js"}}}`,
			"packages/m/src/index.js": "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js":                  fmt.Sprintf(load, "#m"),
		}, true},
		{"workspace member with a development export", map[string]string{
			"package.json":            fmt.Sprintf(workspace, ""),
			"packages/m/package.json": `{"name":"m","exports":{".":{"development":"./dev.js","default":"./src/index.js"}}}`,
			"packages/m/src/index.js": "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js":                  fmt.Sprintf(load, "m"),
		}, true},
		{"workspace member subpath with a development branch in a fallback array", map[string]string{
			"package.json":            fmt.Sprintf(workspace, ""),
			"packages/m/package.json": `{"name":"m","exports":{"./x":[{"development":"./dev.js"},"./x.js"]}}`,
			"packages/m/x.js":         "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js":                  fmt.Sprintf(load, "m/x"),
		}, true},
		{"installed package with a development export", map[string]string{
			"package.json":                    `{"name":"app","dependencies":{"json5":"2.2.1"}}`,
			"node_modules/json5/package.json": `{"name":"json5","exports":{".":{"development":"./dev.js","default":"./lib/index.js"}}}`,
			"app.js":                          fmt.Sprintf(load, "json5"),
		}, true},
		{"installed package subpath with a types branch", map[string]string{
			"package.json":                  `{"name":"app","dependencies":{"pkg":"1.0.0"}}`,
			"node_modules/pkg/package.json": `{"name":"pkg","exports":{"./x":{"types":"./x.d.ts","default":"./x.js"}}}`,
			"app.js":                        fmt.Sprintf(load, "pkg/x"),
		}, true},
		{"scoped package installed above the importing file", map[string]string{
			"package.json":                   `{"name":"app","dependencies":{"@s/p":"1.0.0"}}`,
			"node_modules/@s/p/package.json": `{"name":"@s/p","exports":{"edge-light":"./edge.js","default":"./index.js"}}`,
			"src/app.js":                     fmt.Sprintf(load, "@s/p"),
		}, true},
		{"self-reference through its own exports with a development branch", map[string]string{
			"package.json": `{"name":"app","exports":{".":{"development":"./dev.js","default":"./src/index.js"}}}`,
			"src/index.js": "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js":       fmt.Sprintf(load, "app"),
		}, true},
		{"workspace member a tsconfig paths alias shadows", map[string]string{
			"package.json":            fmt.Sprintf(workspace, ""),
			"tsconfig.json":           `{"compilerOptions":{"baseUrl":".","paths":{"m":["packages/m/src/index.js"]}}}`,
			"packages/m/package.json": `{"name":"m","exports":{".":{"development":"./dist/dev.js","default":"./src/index.js"}}}`,
			"packages/m/src/index.js": "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js":                  fmt.Sprintf(load, "m"),
		}, true},
		{"installed package a tsconfig paths alias shadows", map[string]string{
			"package.json":                  `{"name":"app"}`,
			"tsconfig.json":                 `{"compilerOptions":{"baseUrl":".","paths":{"cfg":["src/cfg.js"]}}}`,
			"src/cfg.js":                    "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"node_modules/cfg/package.json": `{"name":"cfg","exports":{".":{"development":"./dev.js","default":"./prod.js"}}}`,
			"app.js":                        fmt.Sprintf(load, "cfg"),
		}, true},
		{"control: tsconfig paths alias over a package with default keys only", map[string]string{
			"package.json":                  `{"name":"app"}`,
			"tsconfig.json":                 `{"compilerOptions":{"baseUrl":".","paths":{"cfg":["src/cfg.js"]}}}`,
			"src/cfg.js":                    "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"node_modules/cfg/package.json": `{"name":"cfg","exports":{".":{"import":"./i.js","default":"./prod.js"}}}`,
			"app.js":                        fmt.Sprintf(load, "cfg"),
		}, false},
		{"control: installed package with default keys only", map[string]string{
			"package.json":                    `{"name":"app","dependencies":{"json5":"2.2.1"}}`,
			"node_modules/json5/package.json": `{"name":"json5","exports":{".":{"import":"./dist/index.mjs","require":"./lib/index.js"}}}`,
			"app.js":                          fmt.Sprintf(load, "json5"),
		}, false},
		{"control: package not installed", map[string]string{
			"package.json": `{"name":"app","dependencies":{"json5":"2.2.1"}}`,
			"app.js":       fmt.Sprintf(load, "json5"),
		}, false},
		{"control: self-reference with default keys only", map[string]string{
			"package.json": `{"name":"app","exports":{".":{"import":"./src/index.js","default":"./src/index.js"}}}`,
			"src/index.js": "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js":       fmt.Sprintf(load, "app"),
		}, false},
		{"control: #-subpath with default keys only", map[string]string{
			"package.json":     `{"name":"app","imports":{"#cfg":{"import":"./plugins/index.js","require":"./plugins/index.js","default":"./plugins/index.js"}}}`,
			"plugins/index.js": "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js":           fmt.Sprintf(load, "#cfg"),
		}, false},
		{"control: workspace member with default keys only", map[string]string{
			"package.json":            fmt.Sprintf(workspace, ""),
			"packages/m/package.json": `{"name":"m","exports":{".":{"import":"./src/index.js","default":"./src/index.js"}}}`,
			"packages/m/src/index.js": "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js":                  fmt.Sprintf(load, "m"),
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeProgram(t, tc.files)})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonDynamicImportSpecifier); got != tc.want {
				t.Errorf("%s declared = %v, want %v; reasons %v", plugin.PartialReasonDynamicImportSpecifier, got, tc.want, res.Partiality.Reasons)
			}
		})
	}
}
