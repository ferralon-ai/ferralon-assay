package jsanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// craManifest is a stock Create React App package.json.
const craManifest = `{"name":"app","version":"0.1.0","private":true,"proxy":"http://127.0.0.1:5000",
"dependencies":{"react":"^18.2.0","react-dom":"^18.2.0","react-scripts":"5.0.1"},
"scripts":{"start":"react-scripts start","build":"react-scripts build","test":"react-scripts test","eject":"react-scripts eject"},
"eslintConfig":{"extends":["react-app"]},"browserslist":{"production":[">0.2%"],"development":["last 1 chrome version"]}}`

// TestCallGraph_StylesheetImport: a relative import of a stylesheet raises no unresolved_module
// only when it has a stylesheet extension, names a regular file the build-tree walk visits, the
// importing module's package is a stock Create React App, and neither the tree nor a directory
// above it holds a bundler, transform or hook. Every other case keeps the limit. The exempt
// import still declares the loader runtime as a limit scoped to the loader packages.
//
// Unless a case sets noCRA or writes its own package.json, the build root holds craManifest. The
// build root's parent holds .git, which ends the walk above the root there.
func TestCallGraph_StylesheetImport(t *testing.T) {
	const css = "body { margin: 0; }\n"
	cases := []struct {
		name       string
		spec       string
		files      map[string]string // relative to the build root
		noCRA      bool
		setup      func(t *testing.T, root string)
		unresolved bool
	}{
		// All three conditions hold.
		{name: "in-tree css", spec: "./index.css", files: map[string]string{"src/index.css": css}},
		{name: "in-tree css in a parent directory", spec: "../styles/app.css", files: map[string]string{"styles/app.css": css}},
		{name: "in-tree scss", spec: "./theme.scss", files: map[string]string{"src/theme.scss": "$c: red;\n"}},
		{name: "in-tree sass", spec: "./theme.sass", files: map[string]string{"src/theme.sass": "$c: red\n"}},
		{name: "in-tree less", spec: "./theme.less", files: map[string]string{"src/theme.less": "@c: red;\n"}},
		{name: "in-tree CSS Modules file", spec: "./App.module.css", files: map[string]string{"src/App.module.css": ".a { color: red; }\n"}},
		{name: "in-tree symlink to an in-tree css", spec: "./link.css", files: map[string]string{"styles/app.css": css},
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "styles", "app.css"), filepath.Join(root, "src", "link.css"))
			}},
		{name: "a package.json with no transform keys", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","scripts":{"start":"react-scripts start"},"dependencies":{"react-scripts":"5.0.1"},"jest":{"testEnvironment":"node"}}`}},
		{name: "react-scripts as a devDependency with a range", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","devDependencies":{"react-scripts":"^5.0.1"},"scripts":{"build":"react-scripts build --stats"}}`}},
		{name: "a CRA manifest governing from above the importing module", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"backend","scripts":{"start":"node server"}}`, "src/package.json": craManifest}},
		{name: "a non-CRA backend package elsewhere in the tree", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"server/package.json": `{"name":"backend","main":"server.js","type":"module","scripts":{"start":"node server","dev":"nodemon server"},"dependencies":{"express":"4"},"devDependencies":{"nodemon":"3","concurrently":"8"}}`}},

		// The importing module's package is a stock Create React App.
		{name: "no package.json", spec: "./index.css", files: map[string]string{"src/index.css": css}, noCRA: true, unresolved: true},
		{name: "no react-scripts dependency", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react":"18.2.0"}}`}, unresolved: true},
		{name: "react-scripts from an npm alias", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"npm:@acme/react-scripts@5.0.1"}}`}, unresolved: true},
		{name: "react-scripts from a path", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"file:../react-scripts"}}`}, unresolved: true},
		{name: "react-scripts from git", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"github:acme/react-scripts"}}`}, unresolved: true},
		{name: "react-scripts given a non-string version", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":5}}`}, unresolved: true},
		{name: "a script that is not react-scripts", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":"react-scripts start","serve":"node server.js"}}`}, unresolved: true},
		{name: "a react-scripts subcommand outside the stock four", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"lint":"react-scripts lint"}}`}, unresolved: true},
		{name: "a react-scripts script chained in the shell", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":"react-scripts start --x&&node hook.js"}}`}, unresolved: true},
		{name: "a react-scripts script with a positional argument", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"test":"react-scripts test src"}}`}, unresolved: true},
		{name: "a react-scripts script with a require flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":"react-scripts start --require=./hook.js"}}`}, unresolved: true},
		{name: "a react-scripts script with a config flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"test":"react-scripts test --jestConfig=x"}}`}, unresolved: true},
		{name: "a manifest key outside a stock CRA", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","main":"server.js","dependencies":{"react-scripts":"5.0.1"}}`}, unresolved: true},
		{name: "a jest moduleNameMapper", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"jest":{"moduleNameMapper":{"\\.css$":"<rootDir>/hook.js"}}}`}, unresolved: true},
		{name: "an unreadable scripts field", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":1}}`}, unresolved: true},
		{name: "a non-CRA package.json nearer the importing module", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"src/package.json": `{"name":"inner"}`}, unresolved: true},

		// The extension.
		{name: "in-tree svg", spec: "./logo.svg", files: map[string]string{"src/logo.svg": "<svg/>\n"}, unresolved: true},
		{name: "in-tree file with a stylesheet suffix but another extension", spec: "./index.css.js.map", files: map[string]string{"src/index.css.js.map": "{}"}, unresolved: true},

		// The file.
		{name: "missing css", spec: "./index.css", unresolved: true},
		{name: "css path that is a directory", spec: "./index.css", unresolved: true, setup: func(t *testing.T, root string) {
			if err := os.MkdirAll(filepath.Join(root, "src", "index.css"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "css symlinked outside the build root", spec: "./index.css", unresolved: true, setup: func(t *testing.T, root string) {
			outside := filepath.Join(t.TempDir(), "index.css")
			treeWrite(t, outside, css)
			treeSymlink(t, outside, filepath.Join(root, "src", "index.css"))
		}},
		{name: "css path escaping the build root", spec: "../../index.css", unresolved: true, setup: func(t *testing.T, root string) {
			treeWrite(t, filepath.Join(filepath.Dir(root), "index.css"), css)
		}},
		{name: "css under node_modules", spec: "../node_modules/pkg/dist/index.css", files: map[string]string{"node_modules/pkg/dist/index.css": css}, unresolved: true},
		{name: "css through a symlinked directory into node_modules", spec: "./vendor/index.css", files: map[string]string{"node_modules/pkg/index.css": css}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "node_modules", "pkg"), filepath.Join(root, "src", "vendor"))
			}},

		// The tree holds a bundler or transform config.
		{name: "webpack.config.js", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"webpack.config.js": "module.exports = { module: { rules: [{ test: /\\.css$/, use: './my-loader.js' }] } };\n"}, unresolved: true},
		{name: "webpack.common.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "build/webpack.common.js": "module.exports = {};\n"}, unresolved: true},
		{name: "an ejected Create React App config", spec: "./index.css", files: map[string]string{"src/index.css": css, "config/webpackDevServer.config.js": "module.exports = {};\n"}, unresolved: true},
		{name: "vite.config.ts", spec: "./index.css", files: map[string]string{"src/index.css": css, "vite.config.ts": "export default {};\n"}, unresolved: true},
		{name: "rollup.config.mjs", spec: "./index.css", files: map[string]string{"src/index.css": css, "rollup.config.mjs": "export default {};\n"}, unresolved: true},
		{name: "esbuild.config.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "esbuild.config.js": "\n"}, unresolved: true},
		{name: "an esbuild build script", spec: "./index.css", files: map[string]string{"src/index.css": css, "scripts/esbuild.mjs": "\n"}, unresolved: true},
		{name: "a package.json script running esbuild", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"app","scripts":{"build":"esbuild src/index.js --bundle"}}`}, unresolved: true},
		{name: "a devDependency on esbuild", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"app","devDependencies":{"esbuild":"0.20.0"}}`}, unresolved: true},
		{name: "craco.config.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "craco.config.js": "module.exports = {};\n"}, unresolved: true},
		{name: "config-overrides.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "config-overrides.js": "module.exports = c => c;\n"}, unresolved: true},
		{name: "next.config.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "next.config.js": "module.exports = {};\n"}, unresolved: true},
		{name: "nuxt.config.ts", spec: "./index.css", files: map[string]string{"src/index.css": css, "nuxt.config.ts": "export default {};\n"}, unresolved: true},
		{name: "svelte.config.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "svelte.config.js": "export default {};\n"}, unresolved: true},
		{name: "astro.config.mjs", spec: "./index.css", files: map[string]string{"src/index.css": css, "astro.config.mjs": "export default {};\n"}, unresolved: true},
		{name: "rspack.config.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "rspack.config.js": "module.exports = {};\n"}, unresolved: true},
		{name: ".parcelrc", spec: "./index.css", files: map[string]string{"src/index.css": css, ".parcelrc": "{}\n"}, unresolved: true},
		{name: "babel.config.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "babel.config.js": "module.exports = { plugins: ['x'] };\n"}, unresolved: true},
		{name: ".babelrc", spec: "./index.css", files: map[string]string{"src/index.css": css, ".babelrc": "{}\n"}, unresolved: true},
		{name: ".babelrc.json in a subdirectory", spec: "./index.css", files: map[string]string{"src/index.css": css, "packages/x/.babelrc.json": "{}\n"}, unresolved: true},
		{name: "a package.json browser key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"app","browser":{"./a.js":"./b.js"}}`}, unresolved: true},
		{name: "a package.json babel key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"app","babel":{"plugins":["x"]}}`}, unresolved: true},
		{name: "a package.json alias key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"app","alias":{"x":"./y"}}`}, unresolved: true},
		{name: "a package.json jest.transform", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"app","jest":{"transform":{"\\.css$":"./css-transform.js"}}}`}, unresolved: true},
		{name: "a nested package.json with a browser key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","browser":"./b.js"}`}, unresolved: true},
		{name: "an undecodable package.json", spec: "./index.css", files: map[string]string{"src/index.css": css, "package.json": `{"name":`}, unresolved: true},
		{name: "an undecodable nested package.json", spec: "./index.css", files: map[string]string{"src/index.css": css, "packages/x/package.json": `{"name":`}, unresolved: true},
		{name: "vue.config.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "vue.config.js": "module.exports = {};\n"}, unresolved: true},
		{name: "custom-webpack.config.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "tools/custom-webpack.config.js": "module.exports = {};\n"}, unresolved: true},
		{name: "Webpack.config.js in capitals", spec: "./index.css", files: map[string]string{"src/index.css": css, "Webpack.config.js": "module.exports = {};\n"}, unresolved: true},
		{name: "gatsby-node.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "gatsby-node.js": "exports.onCreateWebpackConfig = () => {};\n"}, unresolved: true},
		{name: "jest.config.js", spec: "./index.css", files: map[string]string{"src/index.css": css, "jest.config.js": "module.exports = { transform: {} };\n"}, unresolved: true},
		{name: "rsbuild.config.ts", spec: "./index.css", files: map[string]string{"src/index.css": css, "rsbuild.config.ts": "export default {};\n"}, unresolved: true},
		{name: "a script running webpack with a config", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"build":"webpack --config tools/prod.js"}}`}, unresolved: true},
		{name: "a script naming a config", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"build":"node build.js --config=tools/prod.js"}}`}, unresolved: true},
		{name: "a script preloading a require hook", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node -r css-modules-require-hook server.js"}}`}, unresolved: true},
		{name: "a script setting NODE_OPTIONS", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"NODE_OPTIONS=--import=./hook.mjs node server.js"}}`}, unresolved: true},
		{name: "a browserify transform key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","browserify":{"transform":["cssify"]}}`}, unresolved: true},
		{name: "a dependency on a build wrapper", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","devDependencies":{"@craco/craco":"7"}}`}, unresolved: true},
		{name: "a dependency on a bundler plugin", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","devDependencies":{"vite-plugin-css":"1"}}`}, unresolved: true},
		{name: "a dependency on a require hook", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","dependencies":{"css-modules-require-hook":"4"}}`}, unresolved: true},
		{name: "a package.json above the build root", spec: "./index.css", files: map[string]string{"src/index.css": css}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeWrite(t, filepath.Join(filepath.Dir(root), "package.json"), `{"name":"workspace"}`)
			}},
		{name: "a webpack config above the build root", spec: "./index.css", files: map[string]string{"src/index.css": css}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeWrite(t, filepath.Join(filepath.Dir(root), "webpack.config.js"), "module.exports = {};\n")
			}},
		{name: "a symlink that leaves the tree", spec: "./index.css", files: map[string]string{"src/index.css": css}, unresolved: true,
			setup: func(t *testing.T, root string) {
				outside := t.TempDir()
				treeSymlink(t, outside, filepath.Join(root, "linked"))
			}},
		{name: "a symlinked directory into node_modules", spec: "./index.css", files: map[string]string{"src/index.css": css, "node_modules/pkg/index.js": ""}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "node_modules", "pkg"), filepath.Join(root, "vendor"))
			}},
		{name: "a package.json symlinked outside the tree", spec: "./index.css", files: map[string]string{"src/index.css": css}, unresolved: true,
			setup: func(t *testing.T, root string) {
				outside := filepath.Join(t.TempDir(), "package.json")
				treeWrite(t, outside, `{"name":"app"}`)
				treeSymlink(t, outside, filepath.Join(root, "package.json"))
			}},
		{name: "a dangling symlink to a file does not count", spec: "./index.css", files: map[string]string{"src/index.css": css},
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "missing.txt"), filepath.Join(root, "notes.txt"))
			}},
		{name: "a webpack config under node_modules does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"node_modules/pkg/webpack.config.js": "module.exports = {};\n"}},
		{name: "an in-tree symlinked directory the walk reads does not count", spec: "./index.css", files: map[string]string{"src/index.css": css, "shared/a.js": ""},
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "shared"), filepath.Join(root, "linked"))
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Mkdir(filepath.Join(parent, ".git"), 0o755); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(parent, "build")
			treeWrite(t, filepath.Join(root, "src", "index.js"), "import '"+tc.spec+"';\nfunction load(s) { return s.trim(); }\nload(process.argv);\n")
			if _, own := tc.files["package.json"]; !own && !tc.noCRA {
				treeWrite(t, filepath.Join(root, "package.json"), craManifest)
			}
			for name, body := range tc.files {
				treeWrite(t, filepath.Join(root, filepath.FromSlash(name)), body)
			}
			if tc.setup != nil {
				tc.setup(t, root)
			}
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: root})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if len(res.Edges) == 0 {
				t.Fatalf("fixture must have edges")
			}
			got := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonUnresolvedModule)
			if got != tc.unresolved {
				t.Errorf("unresolved_module = %v, want %v (reasons %v)", got, tc.unresolved, res.Partiality.Reasons)
			}
			runtime := slices.ContainsFunc(res.Partiality.Scoped, func(s plugin.ScopedReason) bool {
				return reflect.DeepEqual(s, stylesheetRuntime())
			})
			if runtime == tc.unresolved || res.Partiality.Complete {
				t.Errorf("loader runtime limit = %v, complete = %v; want the limit exactly when exempt (scoped %v)",
					runtime, res.Partiality.Complete, res.Partiality.Scoped)
			}
		})
	}
}

// TestStyleToolingIn_UnreadableDirectory: a directory the walk cannot read counts as tooling.
// CallGraph's own scan fails on such a tree first, so this pins the rule directly.
func TestStyleToolingIn_UnreadableDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "build")
	treeWrite(t, filepath.Join(root, "src", "index.css"), "body { margin: 0; }\n")
	treeWrite(t, filepath.Join(root, "locked", "a.js"), "")
	dir := filepath.Join(root, "locked")
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if _, err := os.ReadDir(dir); err == nil {
		t.Skip("directory permissions are not enforced for this user")
	}
	if !styleToolingIn(root) {
		t.Error("styleToolingIn = false, want true for an unreadable directory")
	}
}

func treeSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func treeWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
