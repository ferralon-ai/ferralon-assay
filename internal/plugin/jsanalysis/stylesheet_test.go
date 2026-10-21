package jsanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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
		from       string            // the importing module; src/index.js when empty
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
		{name: "a CRA manifest governing from above the importing module", spec: "./index.css", from: "web/src/app/index.js", files: map[string]string{
			"web/src/app/index.css": css, "package.json": `{"name":"backend","scripts":{"start":"node server"}}`, "server.js": "",
			"web/package.json": craManifest}},
		{name: "a module nested under src", spec: "./App.css", from: "src/components/App.js", files: map[string]string{"src/components/App.css": css}},
		{name: "a stock test script with harmless flags", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"^5.0.1"},"scripts":{"test":"react-scripts test --env=jsdom --watchAll=false --coverage"}}`}},
		{name: "a server package with the scripts of a full-stack app", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{
			"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"backend/server.js": "import express from 'express'\nimport path from 'path'\nimport routes from './routes.js'\n",
			"backend/routes.js": "export default []\n",
			"backend/seeder.js": "import mongoose from 'mongoose'\nimport dotenv from 'dotenv'\n",
			"package.json": `{"name":"shop","version":"1.0.0","main":"server.js","type":"module","workspaces":["frontend"],"scripts":{` +
				`"start":"node backend/server","server":"nodemon backend/server","client":"npm start --prefix frontend",` +
				`"dev":"concurrently -k \"npm run server\" \"npm run client\"","data:destroy":"node backend/seeder -d",` +
				`"heroku-postbuild":"NPM_CONFIG_PRODUCTION=false npm install --prefix frontend && npm run build --prefix=frontend",` +
				`"test":"echo \"Error: no test specified\" && exit 1","ci":"NODE_ENV=test npm ci --silent && yarn run build --cwd frontend"},` +
				`"dependencies":{"express":"^4.17.1"},"devDependencies":{"concurrently":"^5.3.0","nodemon":"^2.0.4"}}`}},
		{name: "a non-CRA backend package elsewhere in the tree", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"server/package.json": `{"name":"backend","main":"server.js","type":"module","scripts":{"start":"node server","dev":"nodemon server"},"dependencies":{"express":"4"},"devDependencies":{"nodemon":"3","concurrently":"8"}}`,
			"server/server.js":    ""}},

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
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":"react-scripts start","serve":"node server.js"}}`, "server.js": ""}, unresolved: true},
		{name: "a script that names a react-scripts subcommand without react-scripts", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":"react-scripts start","build":"echo build"}}`}, unresolved: true},
		{name: "a react-scripts subcommand outside the stock four", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"lint":"react-scripts lint"}}`}, unresolved: true},
		{name: "a react-scripts script chained in the shell", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":"react-scripts start --x&&node hook.js"}}`, "hook.js": ""}, unresolved: true},
		{name: "a react-scripts script with a positional argument", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"test":"react-scripts test src"}}`}, unresolved: true},
		{name: "a react-scripts script with a require flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":"react-scripts start --require=./hook.js"}}`}, unresolved: true},
		{name: "a react-scripts script with a config flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"test":"react-scripts test --jestConfig=x"}}`}, unresolved: true},
		{name: "another command given a stock subcommand", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":"react-scripts start","serve":"node start"}}`}, unresolved: true},
		{name: "a react-scripts flag carrying shell syntax", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":"react-scripts start --x;node"}}`}, unresolved: true},
		{name: "a package.json that is a directory", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"src/package.json/.keep": ""}, unresolved: true},
		{name: "a governing package.json that is a directory", spec: "./index.css", from: "web/src/index.js", files: map[string]string{
			"web/src/index.css": css, "web/package.json/.keep": ""}, unresolved: true},
		{name: "a manifest key outside a stock CRA", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","main":"server.js","dependencies":{"react-scripts":"5.0.1"}}`}, unresolved: true},
		{name: "a jest moduleNameMapper", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"jest":{"moduleNameMapper":{"\\.css$":"<rootDir>/hook.js"}}}`}, unresolved: true},
		{name: "an unreadable scripts field", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":1}}`}, unresolved: true},
		{name: "a non-CRA package.json nearer the importing module", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"src/package.json": `{"name":"inner"}`}, unresolved: true},
		{name: "an importing module beside the CRA manifest, outside src", spec: "./index.css", from: "index.js", files: map[string]string{"index.css": css}, unresolved: true},
		{name: "an importing module in a server directory of the CRA package", spec: "./index.css", from: "server/index.js", files: map[string]string{"server/index.css": css}, unresolved: true},
		{name: "a CRA manifest in src governing src itself", spec: "./index.css", files: map[string]string{"src/index.css": css, "package.json": `{"name":"backend"}`, "src/package.json": craManifest}, unresolved: true},
		{name: "react-scripts given the current directory", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"."}}`}, unresolved: true},
		{name: "react-scripts given the parent directory", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":".."}}`}, unresolved: true},
		{name: "react-scripts given a dotted path that is no range", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":".5"}}`}, unresolved: true},
		{name: "react-scripts given a tag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"latest"}}`}, unresolved: true},
		{name: "react-scripts given a range with no version", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"^ -"}}`}, unresolved: true},
		{name: "a jest resolver flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"test":"react-scripts test --resolver=./resolver.js"}}`}, unresolved: true},
		{name: "a jest preset flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"test":"react-scripts test --preset=acme"}}`}, unresolved: true},
		{name: "a jest setupFiles flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"test":"react-scripts test --setupFiles=./hook.js"}}`}, unresolved: true},
		{name: "a jest environment outside the stock two", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"test":"react-scripts test --env=./env.js"}}`}, unresolved: true},
		{name: "a bare react-scripts", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": `{"name":"app","dependencies":{"react-scripts":"5.0.1"},"scripts":{"start":"react-scripts"}}`}, unresolved: true},

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
			"packages/x/package.json": `{"name":"x","scripts":{"build":"node build.js --config=tools/prod.js"}}`, "packages/x/build.js": ""}, unresolved: true},
		{name: "a script preloading a require hook", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node -r css-modules-require-hook server.js"}}`}, unresolved: true},
		{name: "a script setting NODE_OPTIONS", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"NODE_OPTIONS=--import=./hook.mjs node server.js"}}`, "packages/x/server.js": ""}, unresolved: true},
		{name: "a browserify transform key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","browserify":{"transform":["cssify"]}}`}, unresolved: true},
		{name: "a dependency on a build wrapper", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","devDependencies":{"@craco/craco":"7"}}`}, unresolved: true},
		{name: "a dependency on a bundler plugin", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","devDependencies":{"vite-plugin-css":"1"}}`}, unresolved: true},
		{name: "a dependency on a scoped framework package", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","dependencies":{"@nuxt/kit":"3"}}`}, unresolved: true},
		{name: "a dependency naming a bundler mid-name", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","devDependencies":{"gulp-webpack":"1"}}`}, unresolved: true},
		{name: "a dependency named in capitals", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","devDependencies":{"Browserify":"17"}}`}, unresolved: true},
		{name: "a script that is not a string", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"build":1}}`}, unresolved: true},
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
		{name: "a package.json symlinked outside the tree", spec: "./index.css", files: map[string]string{"src/index.css": css}, noCRA: true, unresolved: true,
			setup: func(t *testing.T, root string) {
				outside := filepath.Join(t.TempDir(), "package.json")
				treeWrite(t, outside, craManifest)
				treeSymlink(t, outside, filepath.Join(root, "package.json"))
			}},
		{name: "pnpm-workspace.yaml", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"pnpm-workspace.yaml": "packages: ['.']\npatchedDependencies:\n  react-scripts@5.0.1: patches/x.patch\n"}, unresolved: true},
		{name: "a pnpm-workspace.yaml above the build root", spec: "./index.css", files: map[string]string{"src/index.css": css}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeWrite(t, filepath.Join(filepath.Dir(root), "pnpm-workspace.yaml"), "overrides:\n  json5: link:./fork\n")
			}},
		{name: ".pnpmfile.cjs", spec: "./index.css", files: map[string]string{"src/index.css": css, ".pnpmfile.cjs": "module.exports = { hooks: {} };\n"}, unresolved: true},
		{name: ".yarnrc.yml", spec: "./index.css", files: map[string]string{"src/index.css": css, ".yarnrc.yml": "packageExtensions: {}\n"}, unresolved: true},
		{name: ".pnp.cjs", spec: "./index.css", files: map[string]string{"src/index.css": css, ".pnp.cjs": "\n"}, unresolved: true},
		{name: "a patches directory", spec: "./index.css", files: map[string]string{"src/index.css": css, "patches/react-scripts+5.0.1.patch": "\n"}, unresolved: true},
		{name: "a postinstall applying patches", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"postinstall":"patch-package"}}`}, unresolved: true},
		{name: "a resolutions key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","resolutions":{"css-loader":"file:./fork"}}`}, unresolved: true},
		{name: "an overrides key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","overrides":{"json5":"npm:fork@1"}}`}, unresolved: true},
		{name: "a pnpm key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","pnpm":{"overrides":{"json5":"1"}}}`}, unresolved: true},
		{name: "a nodemonConfig key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","nodemonConfig":{"execMap":{"js":"node -r hook"}}}`}, unresolved: true},
		{name: "nodemon.json", spec: "./index.css", files: map[string]string{"src/index.css": css, "nodemon.json": `{"execMap":{"js":"node -r hook"}}`}, unresolved: true},
		{name: "a dependency installed from a path", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","dependencies":{"css-loader":"file:./fork"}}`}, unresolved: true},
		{name: "a dependency given a tag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","dependencies":{"express":"latest"}}`}, unresolved: true},
		{name: "a dependency given a non-string version", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","dependencies":{"express":4}}`}, unresolved: true},
		{name: "vitest.config.ts", spec: "./index.css", files: map[string]string{"src/index.css": css, "vitest.config.ts": "export default {};\n"}, unresolved: true},
		{name: "vitest.workspace.ts", spec: "./index.css", files: map[string]string{"src/index.css": css, "vitest.workspace.ts": "export default [];\n"}, unresolved: true},
		{name: "a dependency on vitest", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","devDependencies":{"vitest":"^1.0.0"}}`}, unresolved: true},
		{name: "a dependency on the vite React plugin", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","devDependencies":{"@vitejs/plugin-react":"^4.0.0"}}`}, unresolved: true},
		{name: "a dependency on storybook", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","devDependencies":{"@storybook/react-vite":"^8.0.0"}}`}, unresolved: true},
		{name: "a dependency on bun types", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","devDependencies":{"@types/bun":"^1.0.0"}}`}, unresolved: true},
		{name: "a dependency on ignore-styles", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","dependencies":{"ignore-styles":"^5.0.1"}}`}, unresolved: true},
		{name: ".storybook", spec: "./index.css", files: map[string]string{"src/index.css": css, ".storybook/main.js": "module.exports = {};\n"}, unresolved: true},
		{name: "bunfig.toml", spec: "./index.css", files: map[string]string{"src/index.css": css, "bunfig.toml": "preload = ['./hook.ts']\n"}, unresolved: true},
		{name: "a script running vitest", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"test":"vitest run"}}`}, unresolved: true},
		{name: "a script running bun", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"build":"bun build ./src/index.js"}}`}, unresolved: true},
		{name: "a script running a binary through npx", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"test":"npx vitest"}}`}, unresolved: true},
		{name: "a script running a binary through yarn", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"test":"yarn vitest"}}`}, unresolved: true},
		{name: "a script running a binary through npm exec", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"test":"npm exec vitest"}}`}, unresolved: true},
		{name: "a script appending arguments to another", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"test":"echo hi","t":"npm run test -- --setupFiles=./hook.js"}}`}, unresolved: true},
		{name: "a script running another with an extra argument", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"test":"echo hi","t":"npm run test hook"}}`}, unresolved: true},
		{name: "a script running no script", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"t":"npm run"}}`}, unresolved: true},
		{name: "a script installing a package by name", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"setup":"npm install vitest"}}`}, unresolved: true},
		{name: "a script setting a package-manager config flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"npm start --node-options=--require=./hook.js"}}`}, unresolved: true},
		{name: "a script giving a value to a bare flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"npm start --silent=x"}}`}, unresolved: true},
		{name: "a script with a dangling prefix", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"npm start --prefix"}}`}, unresolved: true},
		{name: "a script with a prefix that is a flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json":          `{"name":"x","scripts":{"start":"npm start --prefix --silent"}}`,
			"packages/x/--silent/package.json": `{"name":"y","scripts":{"start":"echo hi"}}`}, unresolved: true},
		{name: "a script with a bare package manager", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"setup":"yarn"}}`}, unresolved: true},
		{name: "a script setting NODE_PATH", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"NODE_PATH=./shim node server.js"}}`, "packages/x/server.js": ""}, unresolved: true},
		{name: "a script setting npm's node-options", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"NPM_CONFIG_NODE_OPTIONS=-r./hook.js npm start"}}`}, unresolved: true},
		{name: "a script of environment assignments only", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"NODE_ENV=x"}}`}, unresolved: true},
		{name: "a script giving node a flag before the file", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node --experimental-vm-modules server.js"}}`}, unresolved: true},
		{name: "a script giving node a flag named like a file", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node --experimental-vm-modules server.js"}}`, "packages/x/--experimental-vm-modules.js": "", "packages/x/server.js": ""}, unresolved: true},
		{name: "a script giving nodemon only a flag named like a file", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"dev":"nodemon --inspect"}}`, "packages/x/--inspect.js": "", "packages/x/index.js": ""}, unresolved: true},
		{name: "a script giving node no file", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"repl":"node"}}`}, unresolved: true},
		{name: "a script running a file outside the tree", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node ../../server.js"}}`}, unresolved: true},
		{name: "a script running an absolute path", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node /srv/server.js"}}`}, unresolved: true},
		{name: "a script running a home-relative path", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node ~/server.js"}}`}, unresolved: true},
		{name: "a script passing a path outside the tree", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node server.js ../../../x.js"}}`, "packages/x/server.js": ""}, unresolved: true},
		{name: "a script passing an absolute path", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node server.js /srv/x.js"}}`, "packages/x/server.js": ""}, unresolved: true},
		{name: "a script passing a home-relative path", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node server.js ~/x.js"}}`, "packages/x/server.js": ""}, unresolved: true},
		{name: "a script passing a glob", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node server.js scripts/*.js"}}`, "packages/x/server.js": ""}, unresolved: true},
		{name: "a script running an unknown tool", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"ts-node server.ts"}}`}, unresolved: true},
		{name: "a script running a disallowed command beside allowed ones", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node server.js && vitest"}}`, "packages/x/server.js": ""}, unresolved: true},
		{name: "a script ending in &&", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node server.js &&"}}`, "packages/x/server.js": ""}, unresolved: true},
		{name: "an empty script", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"  "}}`}, unresolved: true},
		{name: "concurrently running a disallowed command", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"dev":"concurrently \"node server\" \"vitest\""}}`}, unresolved: true},
		{name: "concurrently nested in concurrently", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"dev":"concurrently \"concurrently 'node a'\""}}`, "packages/x/a.js": ""}, unresolved: true},
		{name: "concurrently given a valued flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"dev":"concurrently -n api,web \"node a\" \"node b\""}}`}, unresolved: true},
		{name: "concurrently given nothing", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"dev":"concurrently"}}`}, unresolved: true},
		{name: "exit with a word", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"t":"exit now"}}`}, unresolved: true},
		{name: "exit with an empty status", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"t":"exit ''"}}`}, unresolved: true},
		{name: "exit with two statuses", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"t":"exit 1 2"}}`}, unresolved: true},
		{name: "npm with an unknown flag", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"echo hi","t":"npm start --foo"}}`}, unresolved: true},
		{name: "a script with an unterminated quote", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"t":"echo 'hi"}}`}, unresolved: true},
		{name: "a script running in the background", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"t":"node a & node b"}}`, "packages/x/a.js": "", "packages/x/b.js": ""}, unresolved: true},
		{name: "a script expanding a glob", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"t":"node scripts/*.js"}}`}, unresolved: true},
		{name: "a script with a newline", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"t":"node a\nvitest"}}`, "packages/x/a.js": ""}, unresolved: true},
		{name: "an .npmrc setting node-options", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "registry=https://registry.npmjs.org/\nnode-options=--require ./hook.js\n"}, unresolved: true},
		{name: "an .npmrc setting pnpmfile", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "registry=https://registry.npmjs.org/\npnpmfile=hooks/p.cjs\n"}, unresolved: true},
		{name: "an .npmrc setting global-pnpmfile", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "registry=https://registry.npmjs.org/\nglobal-pnpmfile=hooks/p.cjs\n"}, unresolved: true},
		{name: "an .npmrc setting script-shell", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "registry=https://registry.npmjs.org/\nscript-shell=./sh.js\n"}, unresolved: true},
		{name: "an .npmrc setting shell", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "registry=https://registry.npmjs.org/\nshell=./sh.js\n"}, unresolved: true},
		{name: "an .npmrc setting onload-script", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "registry=https://registry.npmjs.org/\nonload-script=./hook.js\n"}, unresolved: true},
		{name: "an .npmrc setting userconfig", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "registry=https://registry.npmjs.org/\nuserconfig=./more.npmrc\n"}, unresolved: true},
		{name: "an .npmrc setting globalconfig", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "registry=https://registry.npmjs.org/\nglobalconfig=./more.npmrc\n"}, unresolved: true},
		{name: "an .npmrc setting node-options as an environment name", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/.npmrc": "  NODE_OPTIONS = -r ./hook.js\n"}, unresolved: true},
		{name: "an .npmrc appending to node-options", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "node-options[]=--require ./hook.js\n"}, unresolved: true},
		{name: "an .npmrc symlinked outside the tree", spec: "./index.css", files: map[string]string{"src/index.css": css}, unresolved: true,
			setup: func(t *testing.T, root string) {
				outside := filepath.Join(t.TempDir(), ".npmrc")
				treeWrite(t, outside, "registry=https://registry.npmjs.org/\n")
				treeSymlink(t, outside, filepath.Join(root, ".npmrc"))
			}},
		{name: "an .npmrc above the build root setting node-options", spec: "./index.css", files: map[string]string{"src/index.css": css}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeWrite(t, filepath.Join(filepath.Dir(root), ".npmrc"), "node-options=--require ./hook.js\n")
			}},
		{name: "nodemon given an exec after the file", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"dev":"nodemon server.js --exec \"node -r ./h.js\""}}`, "packages/x/server.js": ""}, unresolved: true},
		{name: "nodemon given a bundler after the file", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"dev":"nodemon server.js -x webpack"}}`, "packages/x/server.js": ""}, unresolved: true},
		{name: "nodemon given a flag before the file", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"dev":"nodemon -x webpack"}}`}, unresolved: true},
		{name: "nodemon given only an option", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"dev":"nodemon --inspect"}}`}, unresolved: true},
		{name: "yarn running an undeclared script, a binary", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"b":"yarn run webpack"}}`}, unresolved: true},
		{name: "yarn starting with no start script", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"b":"yarn start"}}`}, unresolved: true},
		{name: "npm running a script its prefix directory does not declare", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json":   `{"name":"x","scripts":{"b":"npm run build --prefix y"}}`,
			"packages/x/y/package.json": `{"name":"y","scripts":{"start":"echo hi"}}`}, unresolved: true},
		{name: "npm running a script in a prefix directory with no package.json", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"b":"npm run build --prefix y"}}`}, unresolved: true},
		{name: "npm given two prefixes", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json":   `{"name":"x","scripts":{"b":"npm run build --prefix y --prefix z"}}`,
			"packages/x/y/package.json": `{"name":"y","scripts":{"build":"echo hi"}}`,
			"packages/x/z/package.json": `{"name":"z","scripts":{"build":"echo hi"}}`}, unresolved: true},
		{name: "a prefix directory with an undecodable package.json", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json":   `{"name":"x","scripts":{"b":"npm run build --prefix y"}}`,
			"packages/x/y/package.json": `{"scripts":[]}`}, unresolved: true},
		{name: "a jest moduleNameMapper in another package.json", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","jest":{"moduleNameMapper":{"\\.css$":"<rootDir>/evil.js"}}}`}, unresolved: true},
		{name: "a jest that is not an object in another package.json", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","jest":"jest.config.mjs"}`}, unresolved: true},
		{name: "an in-tree package named react-scripts", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"react-scripts","version":"5.0.1"}`}, unresolved: true},
		{name: "an in-tree package named react-dev-utils", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"react-dev-utils","version":"5.0.1"}`}, unresolved: true},
		{name: "an in-tree package named mini-css-extract-plugin", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"mini-css-extract-plugin","version":"5.0.1"}`}, unresolved: true},
		{name: "an in-tree package named sass", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"sass","version":"5.0.1"}`}, unresolved: true},
		{name: "an in-tree package named less", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"less","version":"5.0.1"}`}, unresolved: true},
		{name: "an in-tree package named webpack", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"webpack","version":"5.0.1"}`}, unresolved: true},
		{name: "an in-tree package named css-loader", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"css-loader","version":"5.0.1"}`}, unresolved: true},
		{name: "an in-tree package named postcss-preset-env", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"postcss-preset-env","version":"5.0.1"}`}, unresolved: true},
		{name: "an in-tree package named babel-preset-react-app", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"babel-preset-react-app","version":"5.0.1"}`}, unresolved: true},
		{name: "an in-tree package named @babel/core", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"@babel/core","version":"5.0.1"}`}, unresolved: true},
		{name: "an in-tree package named React-Scripts", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"React-Scripts","version":"5.0.1"}`}, unresolved: true},
		{name: "an in-tree package whose name is not a string", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":1}`}, unresolved: true},
		{name: "a module that requires a bundler", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"tools/build.js": "const webpack = require('webpack');\nwebpack({});\n"}, unresolved: true},
		{name: "a module that imports a scoped tooling package by subpath", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"tools/build.mjs": "import t from '@babel/core/lib/transform.js';\nt();\n"}, unresolved: true},
		{name: "node running a file under build, which the source walk skips", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node build/ssr.js"}}`, "build/ssr.js": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true},
		{name: "node running a .mts file, which the source walk does not parse", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node scripts/build.mts"}}`, "scripts/build.mts": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true},
		{name: "node running a file under a dot-directory", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node .scripts/build.js"}}`, ".scripts/build.js": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true},
		{name: "node running a file under dist", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node dist/build.js"}}`, "dist/build.js": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true},
		{name: "node running a file under node_modules", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node node_modules/webpack/bin/webpack.js"}}`, "node_modules/webpack/bin/webpack.js": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true},
		{name: "node running a file under the app's src, which the import scan leaves to react-scripts", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node frontend/src/build.js"}}`, "frontend/src/build.js": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true},
		{name: "node running an extensionless file", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node tools/build"}}`, "tools/build": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true},
		{name: "node running a directory", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node tools"}}`, "tools/index.js": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true},
		{name: "node running a missing file", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node tools/build.js"}}`}, unresolved: true},
		{name: "node running a directory named like a file", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node tools/build.js"}}`, "tools/build.js/index.js": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true},
		{name: "node running a link without a JS extension to a module", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node tools/build.sh"}}`, "tools/build.js": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "tools", "build.js"), filepath.Join(root, "tools", "build.sh"))
			}},
		{name: "node running a link to a file without a JS extension", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node tools/build.js"}}`, "tools/build.txt": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "tools", "build.txt"), filepath.Join(root, "tools", "build.js"))
			}},
		{name: "node running a link in the app's src to a module outside it", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node frontend/src/build.js"}}`, "tools/build.js": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "tools", "build.js"), filepath.Join(root, "frontend", "src", "build.js"))
			}},
		{name: "node running a link to a module in the app's src", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node tools/build.js"}}`, "frontend/src/build.js": "const r = require('fs');\nr.readFileSync('x');\n", "tools/.keep": ""}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "frontend", "src", "build.js"), filepath.Join(root, "tools", "build.js"))
			}},
		{name: "node running a link under dist to a module outside it", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node dist/build.js"}}`, "tools/build.js": "const r = require('fs');\nr.readFileSync('x');\n", "dist/.keep": ""}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "tools", "build.js"), filepath.Join(root, "dist", "build.js"))
			}},
		{name: "node running a link to a module under dist", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node tools/build.js"}}`, "dist/build.js": "const r = require('fs');\nr.readFileSync('x');\n", "tools/.keep": ""}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "dist", "build.js"), filepath.Join(root, "tools", "build.js"))
			}},
		{name: "nodemon running a file under build", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"nodemon build/ssr.js"}}`, "build/ssr.js": "const r = require('fs');\nr.readFileSync('x');\n"}, unresolved: true},
		{name: "a script running a module that loads rolldown", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node tools/build.js"}}`, "tools/build.js": "require('rolldown').build({input: 'frontend/src/index.js'});\n"}, unresolved: true},
		{name: "a script running a module that loads tsup", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node tools/build.js"}}`, "tools/build.js": "require('tsup').build({entry: ['frontend/src/index.js']});\n"}, unresolved: true},
		{name: "a module outside src that loads an unlisted scoped package", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"server/index.js": "import('@scope/pkg');\n"}, unresolved: true},
		{name: "a module outside src that loads a file in the app's src", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"server/index.js": "require('../src/build.js');\n", "src/build.js": "require('fs');\n"}, unresolved: true},
		{name: "a module outside src that loads the app's src directory", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"server/index.js": "require('../src');\n"}, unresolved: true},
		{name: "a module outside src that loads a package directory in the app's src", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"server/index.js": "require('../src/lib');\n", "src/lib/package.json": `{"name":"lib","main":"main.js"}`, "src/lib/main.js": "require('fs');\n"}, unresolved: true},
		{name: "a module outside src that loads an absolute path", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"server/index.js": "require('/opt/build.js');\n"}, unresolved: true},
		{name: "an in-tree package named as a listed server package", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"server/express/package.json": `{"name":"express","version":"4.17.1"}`}, unresolved: true},
		{name: "an .npmrc setting node-options under a double-quoted key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "\"node-options\"=--require ./css-hook.js\n"}, unresolved: true},
		{name: "an .npmrc setting node-options under a single-quoted key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "'node-options' = --require ./css-hook.js\n"}, unresolved: true},
		{name: "an .npmrc setting pnpmfile under a quoted key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "\"pnpmfile\"=hooks/p.cjs\n"}, unresolved: true},
		{name: "an .npmrc in the app's directory setting node-options under a quoted key", spec: "./index.css", from: "frontend/src/index.js",
			files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest, "frontend/.npmrc": "\"node-options\"=--require ./css-hook.js\n"}, unresolved: true},
		{name: "an .npmrc setting node-options after a byte-order mark", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "\ufeffnode-options=--require ./css-hook.js\n"}, unresolved: true},
		{name: "an .npmrc in the app's directory setting pnpmfile after a byte-order mark", spec: "./index.css", from: "frontend/src/index.js",
			files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest, "frontend/.npmrc": "\ufeffpnpmfile=hooks/p.cjs\n"}, unresolved: true},
		{name: "an .npmrc with carriage-return line ends setting node-options", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "registry=https://registry.npmjs.org/\rnode-options=--require ./css-hook.js\r"}, unresolved: true},
		{name: "an .npmrc setting node-options under an escaped quoted key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "\"node\\u002doptions\"=--require ./css-hook.js\n"}, unresolved: true},
		{name: "an .npmrc setting node-options under a doubly quoted key", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "'\"node-options\"'=--require ./css-hook.js\n"}, unresolved: true},
		{name: "an .npmrc setting node-options under a key with a substitution", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "node-options${NOPE?}=--require ./css-hook.js\n"}, unresolved: true},
		{name: "a script running node on a declaration file", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"build":"node tools/build.d.ts"}}`, "packages/x/tools/build.d.ts": "require('webpack');\n"}, unresolved: true},
		{name: "a script running nodemon on a declaration file", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"build":"nodemon tools/build.d.ts"}}`, "packages/x/tools/build.d.ts": "require('webpack');\n"}, unresolved: true},
		{name: "a script running node on a file named in another case", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"build":"node tools/build.js"}}`, "packages/x/tools/build.JS": "require('webpack');\n"}, unresolved: true},
		{name: "a script running nodemon on a TypeScript file", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"dev":"nodemon server/index.ts"}}`, "packages/x/server/index.ts": "export {};\n",
			"packages/x/tsconfig.json": `{"ts-node":{"require":["./dist/build.js"]}}`}, unresolved: true},
		{name: "a script running nodemon on a file linked to a TypeScript file", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"dev":"nodemon server/index.js"}}`, "packages/x/server/main.ts": "export {};\n"}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "packages/x/server/main.ts"), filepath.Join(root, "packages/x/server/index.js"))
			}},
		{name: "a script setting BROWSER to a script", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"BROWSER=./open.js node server.js"}}`, "packages/x/server.js": ""}, unresolved: true},
		{name: "a script installing with a prefix into node_modules", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"setup":"npm install --prefix node_modules/tool"}}`}, unresolved: true},
		{name: "a script starting with a prefix into node_modules", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json":                     `{"name":"x","scripts":{"b":"npm start --prefix=a/node_modules/tool"}}`,
			"packages/x/a/node_modules/tool/package.json": `{"name":"tool","scripts":{"start":"echo hi"}}`}, unresolved: true},
		{name: "a .git file above the build root does not end the walk", spec: "./index.css", files: map[string]string{"src/index.css": css}, unresolved: true,
			setup: func(t *testing.T, root string) {
				treeWrite(t, filepath.Join(root, ".git"), "gitdir: ../.git/modules/build\n")
				treeWrite(t, filepath.Join(filepath.Dir(root), "package.json"), `{"name":"workspace"}`)
			}},
		{name: "a script with tab-separated words does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"node\tserver.js"}}`, "packages/x/server.js": ""}},
		{name: "a dangling symlink to a file does not count", spec: "./index.css", files: map[string]string{"src/index.css": css},
			setup: func(t *testing.T, root string) {
				treeSymlink(t, filepath.Join(root, "missing.txt"), filepath.Join(root, "notes.txt"))
			}},
		{name: "a webpack config under node_modules does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"node_modules/pkg/webpack.config.js": "module.exports = {};\n"}},
		{name: "an .npmrc with registry settings only does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "registry=https://registry.npmjs.org/\n# node-options=--require ./hook.js\n; pnpmfile=x.cjs\nsave-exact=true\n"}},
		{name: "an .npmrc above the build root with registry settings only does not count", spec: "./index.css", files: map[string]string{"src/index.css": css},
			setup: func(t *testing.T, root string) {
				treeWrite(t, filepath.Join(filepath.Dir(root), ".npmrc"), "registry=https://registry.npmjs.org/\n")
			}},
		{name: "a jest key of allowed overrides in another package.json does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","jest":{"testEnvironment":"node"}}`}},
		{name: "an in-tree package named like no tooling does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"rs/package.json": `{"name":"lessons","version":"1.0.0"}`}},
		{name: "a module that loads a non-tooling package or a builtin does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"server/index.js": "const express = require('express');\nconst fs = require('node:fs');\nconst p = require('path');\nimport('cors');\nexpress(fs, p);\n"}},
		{name: "a script running a module that loads only listed packages does not count", spec: "./index.css", from: "frontend/src/index.js", files: map[string]string{"frontend/src/index.css": css, "frontend/package.json": craManifest,
			"package.json": `{"name":"shop","scripts":{"build:ssr":"node tools/build.js"}}`, "tools/build.js": "require('express');\nrequire('dotenv').config();\n"}},
		{name: "an app module loading a runtime package named like a loader does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"src/Skeleton.js": "import ContentLoader from 'react-content-loader';\nContentLoader();\n"}},
		{name: "an app module loading a scoped package named like a loader does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"src/Map.js": "import { Loader } from '@googlemaps/js-api-loader';\nnew Loader();\n"}},
		{name: "an app module loading a Babel polyfill does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"src/polyfills.js": "import '@babel/polyfill';\n"}},
		{name: "an app named like a bundler does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"package.json": strings.Replace(craManifest, `"name":"app"`, `"name":"parcel-tracker"`, 1)}},
		{name: "an .npmrc with a quoted key that is no hook does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			".npmrc": "\"registry\"=https://registry.npmjs.org/\n"}},
		{name: "a script setting BROWSER to none does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json": `{"name":"x","scripts":{"start":"BROWSER=none node server.js"}}`, "packages/x/server.js": ""}},
		{name: "npm running a script its prefix directory declares does not count", spec: "./index.css", files: map[string]string{"src/index.css": css,
			"packages/x/package.json":   `{"name":"x","scripts":{"b":"npm run build --prefix y"}}`,
			"packages/x/y/package.json": `{"name":"y","scripts":{"build":"echo hi"}}`}},
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
			from := tc.from
			if from == "" {
				from = "src/index.js"
			}
			treeWrite(t, filepath.Join(root, filepath.FromSlash(from)), "import '"+tc.spec+"';\nfunction load(s) { return s.trim(); }\nload(process.argv);\n")
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

// TestStylesheetRuntimeAlone: a program whose only limit is the loader runtime of an exempt
// stylesheet import is incomplete, with that limit scoped and no run-wide reason, in both the call
// graph and reachability (which must not widen it to dynamic_dispatch).
func TestStylesheetRuntimeAlone(t *testing.T) {
	parent := t.TempDir()
	if err := os.Mkdir(filepath.Join(parent, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "build")
	treeWrite(t, filepath.Join(root, "package.json"), craManifest)
	treeWrite(t, filepath.Join(root, "src", "index.css"), "body { margin: 0; }\n")
	treeWrite(t, filepath.Join(root, "src", "index.js"), "import './index.css';\nfunction parse() { return 1; }\nfunction load() { return parse(); }\nload();\n")
	want := []plugin.ScopedReason{stylesheetRuntime()}

	cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: root})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if cg.Partiality.Complete || len(cg.Partiality.Reasons) != 0 || !reflect.DeepEqual(cg.Partiality.Scoped, want) {
		t.Fatalf("call graph partiality = %+v; want incomplete with only %+v", cg.Partiality, want)
	}
	var sink string
	for _, e := range cg.Edges {
		if e.Callee.SCIP != "" && strings.HasSuffix(e.Callee.SCIP, "parse().") {
			sink = e.Callee.SCIP
		}
	}
	if sink == "" {
		t.Fatalf("no edge into parse in %+v", cg.Edges)
	}
	reach, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: root, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(reach.Paths) == 0 {
		t.Fatalf("parse must be reachable")
	}
	if reach.Partiality.Complete || len(reach.Partiality.Reasons) != 0 || !reflect.DeepEqual(reach.Partiality.Scoped, want) {
		t.Errorf("reachability partiality = %+v; want incomplete with only %+v", reach.Partiality, want)
	}
}

// TestStyleToolingAbove_UnreadableParent: a directory above the build root that cannot be listed
// counts as tooling.
func TestStyleToolingAbove_UnreadableParent(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "build")
	treeWrite(t, filepath.Join(root, "src", "index.css"), "body { margin: 0; }\n")
	if err := os.Chmod(parent, 0o311); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	if _, err := os.ReadDir(parent); err == nil {
		t.Skip("directory permissions are not enforced for this user")
	}
	if !styleToolingIn(root) {
		t.Error("styleToolingIn = false, want true for an unlistable parent")
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
