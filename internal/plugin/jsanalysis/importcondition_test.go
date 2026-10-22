package jsanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// TestCallGraph_PathsShadowedLoadKeepsLimit: Node ignores tsconfig `paths`, so a bare
// specifier an alias claims loads whatever Node itself resolves: a core module, the
// governing package's own exports, or a node_modules candidate. Any of those keeps
// uninspectable_package for every load form, whatever conditions the package declares. The
// controls load the alias target only.
func TestCallGraph_PathsShadowedLoadKeepsLimit(t *testing.T) {
	forms := map[string]string{
		"import()": "async function load(s) { const m = await import('%s'); return m.parse(s); }\nload(process.argv);\n",
		"import":   "import m from '%s';\nfunction load(s) { return m.parse(s); }\nload(process.argv);\n",
		"require":  "const m = require('%s');\nfunction load(s) { return m.parse(s); }\nload(process.argv);\n",
	}
	const parse = "function parse(s) { return s; }\nmodule.exports = { parse };\n"
	cases := []struct {
		name  string
		spec  string
		files map[string]string
		want  bool
	}{
		{"scoped package installed under a wildcard alias", "@app/plugins", map[string]string{
			"package.json":                           `{"name":"app"}`,
			"tsconfig.json":                          `{"compilerOptions":{"paths":{"@app/*":["./*"]}}}`,
			"plugins/index.js":                       parse,
			"node_modules/@app/plugins/package.json": `{"name":"@app/plugins","main":"index.js"}`,
		}, true},
		{"installed package with default keys only", "cfg", map[string]string{
			"package.json":                  `{"name":"app"}`,
			"tsconfig.json":                 `{"compilerOptions":{"baseUrl":".","paths":{"cfg":["src/cfg.js"]}}}`,
			"src/cfg.js":                    parse,
			"node_modules/cfg/package.json": `{"name":"cfg","exports":{".":{"import":"./i.js","default":"./prod.js"}}}`,
		}, true},
		{"installed package with no package.json", "cfg", map[string]string{
			"package.json":              `{"name":"app"}`,
			"tsconfig.json":             `{"compilerOptions":{"baseUrl":".","paths":{"cfg":["src/cfg.js"]}}}`,
			"src/cfg.js":                parse,
			"node_modules/cfg/index.js": "exports.parse = (s) => s;\n",
		}, true},
		{"installed single-file module", "cfg", map[string]string{
			"package.json":        `{"name":"app"}`,
			"tsconfig.json":       `{"compilerOptions":{"baseUrl":".","paths":{"cfg":["src/cfg.js"]}}}`,
			"src/cfg.js":          parse,
			"node_modules/cfg.js": "exports.parse = (s) => s;\n",
		}, true},
		{"self-reference through its own exports", "app", map[string]string{
			"package.json":  `{"name":"app","exports":{".":{"import":"./lib/index.js","default":"./lib/index.js"}}}`,
			"tsconfig.json": `{"compilerOptions":{"baseUrl":".","paths":{"app":["src/cfg.js"]}}}`,
			"src/cfg.js":    parse,
		}, true},
		{"core module", "vm", map[string]string{
			"package.json":  `{"name":"app"}`,
			"tsconfig.json": `{"compilerOptions":{"baseUrl":".","paths":{"*":["src/*"]}}}`,
			"src/vm.js":     parse,
		}, true},
		{"control: alias with no installed package", "cfg", map[string]string{
			"package.json":  `{"name":"app"}`,
			"tsconfig.json": `{"compilerOptions":{"baseUrl":".","paths":{"cfg":["src/cfg.js"]}}}`,
			"src/cfg.js":    parse,
		}, false},
		{"control: relative load of the alias target", "./plugins/index.js", map[string]string{
			"package.json":                           `{"name":"app"}`,
			"tsconfig.json":                          `{"compilerOptions":{"paths":{"@app/*":["./*"]}}}`,
			"plugins/index.js":                       parse,
			"node_modules/@app/plugins/package.json": `{"name":"@app/plugins","main":"index.js"}`,
		}, false},
	}
	for _, tc := range cases {
		for form, src := range forms {
			t.Run(tc.name+"/"+form, func(t *testing.T) {
				files := map[string]string{"app.js": fmt.Sprintf(src, tc.spec)}
				for k, v := range tc.files {
					files[k] = v
				}
				res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeProgram(t, files)})
				if err != nil {
					t.Fatalf("CallGraph: %v", err)
				}
				if got := hasReason(res.Partiality, plugin.PartialReasonUninspectablePackage); got != tc.want {
					t.Errorf("%s declared = %v, want %v; reasons %v", plugin.PartialReasonUninspectablePackage, got, tc.want, res.Partiality.Reasons)
				}
			})
		}
	}
}

// TestCallGraph_InstalledManifestFailsClosed: an installed package.json the guard will not
// read (its real path leaves the build root, it is not a regular file, or it is oversized)
// keeps dynamic_import_specifier. An in-tree symlink, the pnpm layout, is read normally.
func TestCallGraph_InstalledManifestFailsClosed(t *testing.T) {
	const dev = `{"name":"x","exports":{"development":"./d.js","default":"./i.js"}}`
	const plain = `{"name":"x","exports":{"import":"./i.js","default":"./i.js"}}`
	cases := []struct {
		name  string
		setup func(t *testing.T, root string)
		want  bool
	}{
		{"package directory symlinked outside the build root", func(t *testing.T, root string) {
			outside := t.TempDir()
			mustWrite(t, filepath.Join(outside, "package.json"), plain)
			mustSymlink(t, outside, filepath.Join(root, "node_modules", "x"))
		}, true},
		{"package.json symlinked to a device", func(t *testing.T, root string) {
			mustSymlink(t, "/dev/zero", filepath.Join(root, "node_modules", "x", "package.json"))
		}, true},
		{"oversized package.json", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "node_modules", "x", "package.json"), plain+strings.Repeat(" ", maxInstalledManifest))
		}, true},
		{"package.json symlink that dangles", func(t *testing.T, root string) {
			mustSymlink(t, filepath.Join(root, "missing.json"), filepath.Join(root, "node_modules", "x", "package.json"))
		}, true},
		{"control: in-tree symlink with default keys only", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "node_modules", ".pnpm", "x@1", "node_modules", "x", "package.json"), plain)
			mustSymlink(t, filepath.Join(root, "node_modules", ".pnpm", "x@1", "node_modules", "x"), filepath.Join(root, "node_modules", "x"))
		}, false},
		{"in-tree symlink with a development export", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "node_modules", ".pnpm", "x@1", "node_modules", "x", "package.json"), dev)
			mustSymlink(t, filepath.Join(root, "node_modules", ".pnpm", "x@1", "node_modules", "x"), filepath.Join(root, "node_modules", "x"))
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeProgram(t, map[string]string{
				"package.json": `{"name":"app"}`,
				"app.js":       "async function load(s) { const m = await import('x'); return m.parse(s); }\nload(process.argv);\n",
			})
			tc.setup(t, root)
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: root})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonDynamicImportSpecifier); got != tc.want {
				t.Errorf("%s declared = %v, want %v; reasons %v", plugin.PartialReasonDynamicImportSpecifier, got, tc.want, res.Partiality.Reasons)
			}
		})
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
