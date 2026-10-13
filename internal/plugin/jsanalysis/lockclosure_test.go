package jsanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLockClosures(t *testing.T) {
	const lock = `{"lockfileVersion":3,"packages":{
"":{"name":"app","workspaces":["packages/*"]},
"node_modules/qs":{"dependencies":{"side-channel":"^1"}},
"node_modules/side-channel":{"dependencies":{"object-inspect":"^1"}},
"node_modules/side-channel/node_modules/object-inspect":{"dependencies":{"nested-only":"1"}},
"node_modules/object-inspect":{},
"node_modules/nested-only":{},
"node_modules/@app/lib":{"link":true,"resolved":"packages/lib"},
"packages/lib":{"name":"@app/lib","dependencies":{"object-inspect":"^1"}},
"packages/lib/node_modules/lib-only":{},
"node_modules/strip":{"name":"strip-ansi","dependencies":{"ansi-regex":"^5"}},
"node_modules/ansi-regex":{},
"node_modules/peerer":{"peerDependencies":{"absent":"*","nested-only":"1"},"peerDependenciesMeta":{"absent":{"optional":true}}},
"node_modules/optdep":{"optionalDependencies":{"fsevents":"*"}},
"node_modules/lone":{},
"sub/node_modules/qs":{},
"sub/node_modules/sub-only":{}
}}`
	dir := writeProgram(t, map[string]string{
		"package-lock.json":        lock,
		"v1/package-lock.json":     `{"lockfileVersion":1,"dependencies":{"qs":{"version":"6.0.0"}}}`,
		"broken/package-lock.json": `{"lockfileVersion":3,"packages":{"":{},"node_modules/ok":{},"node_modules/broken":{"dependencies":{"gone":"1"}}}}`,
		"peer/package-lock.json":   `{"lockfileVersion":3,"packages":{"":{},"node_modules/ok":{},"node_modules/needs-peer":{"peerDependencies":{"gone":"*"}}}}`,
	})
	// Every package installed at the top level is reachable from any package by name,
	// declared or not, and so is everything those packages reach: the link into
	// packages/lib ("" for its first-party code, and lib-only from its own node_modules).
	rootReach := []string{"", "@app/lib", "ansi-regex", "lib-only", "lone", "nested-only", "object-inspect", "optdep", "peerer", "qs", "side-channel", "strip", "strip-ansi"}
	reach := func(pkg string, extra ...string) []string {
		out := []string{pkg}
		for _, n := range rootReach {
			if n != pkg {
				out = append(out, n)
			}
		}
		return append(out, extra...)
	}
	cases := []struct {
		name, from, pkg string
		want            []string
	}{
		{"declared closure plus the hoisted top level", "", "qs", reach("qs")},
		{"resolution walks up from a nested importer", "src/deep", "qs", reach("qs")},
		// sub/node_modules/qs also reaches sub/node_modules, which no root package can.
		{"a nested install adds its own node_modules", "sub", "qs", reach("qs", "sub-only")},
		{"a package with no dependencies still reaches every hoisted package", "", "lone", reach("lone")},
		{"a workspace link is first-party", "", "@app/lib", reach("@app/lib")},
		{"an aliased install answers to both names", "", "strip", reach("strip")},
		{"an absent optional peer bounds nothing away", "", "peerer", reach("peerer")},
		{"an uninstalled optional dependency bounds nothing away", "", "optdep", reach("optdep")},
		{"a reachable package missing a required dependency is unbounded", "broken", "ok", nil},
		{"a reachable package missing a required peer is unbounded", "peer", "ok", nil},
		{"a package the lock does not list is unbounded", "", "not-installed", nil},
		{"a v1 lock is unbounded", "v1", "qs", nil},
	}
	lc := newLockClosures(dir)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lc.closureOf(tc.from, tc.pkg); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("closureOf(%q, %q) = %#v, want %#v", tc.from, tc.pkg, got, tc.want)
			}
		})
	}
	// The disk/lock comparison, each in a tree of its own, since a lock above another one
	// leaves the lower one unbounded.
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"a node_modules on disk that matches the lock is bounded", map[string]string{
			"package-lock.json":                           `{"lockfileVersion":3,"packages":{"":{},"node_modules/ok":{},"node_modules/@s/p":{},"node_modules/ok/node_modules/inner":{}}}`,
			"node_modules/.bin/ok":                        "",
			"node_modules/ok/package.json":                `{"name":"ok"}`,
			"node_modules/@s/p/package.json":              `{"name":"@s/p"}`,
			"node_modules/ok/node_modules/inner/index.js": "",
		}, []string{"ok", "@s/p", "inner"}},
		{"a node_modules on disk holding a package the lock does not list is unbounded", map[string]string{
			"package-lock.json":                           `{"lockfileVersion":3,"packages":{"":{},"node_modules/ok":{}}}`,
			"node_modules/ok/package.json":                `{"name":"ok"}`,
			"node_modules/ok/node_modules/extra/index.js": "",
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := newLockClosures(writeProgram(t, tc.files)).closureOf("", "ok"); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("closureOf = %#v, want %#v", got, tc.want)
			}
		})
	}
	if got := newLockClosures(t.TempDir()).closureOf("", "qs"); got != nil {
		t.Errorf("no lockfile must be unbounded; got %#v", got)
	}
}

// TestLockClosures_LaunchTokens: NODE_PATH adds resolution roots no lockfile lists, and
// NODE_OPTIONS or a node flag can preload code or a loader or keep symlinked paths. Launch
// surfaces are not enumerated: a file anywhere in the build tree (node_modules and
// site-packages aside) that mentions one of these settings leaves every closure unbounded,
// so a mention that sets nothing over-fires by design. The short -r and -C count in any file
// that also names a node command, wherever they sit; a flag that changes neither resolution
// nor preloading leaves the closure bounded. Resolver hooks, a bundler's alias or modules
// setting, and a tsconfig paths setting together with a TypeScript runner leave it unbounded.
func TestLockClosures_LaunchTokens(t *testing.T) {
	const lock = `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/qs":{}}}`
	cases := []struct {
		name    string
		file    string
		body    string
		bounded bool
	}{
		{"Dockerfile ENV with =", "Dockerfile", "FROM node:20\nENV NODE_PATH=/srv/lib\n", false},
		{"Dockerfile ENV with a space", "deploy/Dockerfile.prod", "FROM node:20\nENV NODE_PATH /srv/lib\n", false},
		{"Dockerfile ARG", "Dockerfile", "FROM node:20\nARG NODE_OPTIONS\n", false},
		{"Dockerfile under build/", "build/Dockerfile", "FROM node:20\nENV NODE_PATH=/srv/lib\n", false},
		{"package.json script", "package.json", `{"name":"app","scripts":{"start":"NODE_PATH=src node index.js"}}`, false},
		{"workflow env", ".github/workflows/deploy.yml", "jobs:\n  run:\n    env:\n      NODE_PATH: src\n", false},
		{"CircleCI config", ".circleci/config.yml", "jobs:\n  build:\n    environment:\n      NODE_PATH: lib\n", false},
		{"Procfile", "Procfile", "web: NODE_PATH=lib node server.js\n", false},
		{"Kubernetes env list", "k8s/deployment.yaml", "env:\n  - name: NODE_PATH\n    value: /app/lib\n", false},
		{"compose environment list", "docker-compose.yml", "services:\n  web:\n    environment:\n      - NODE_PATH=/app/lib\n", false},
		{"TOML env table", "fly.toml", "[env]\n  NODE_PATH = \"lib\"\n", false},
		{"env file", ".env.production", "NODE_PATH=lib\n", false},
		{"shell script", "scripts/run.sh", "export NODE_PATH=lib\nnode index.js\n", false},
		{"extensionless start script", "bin/start", "#!/bin/sh\nNODE_PATH=lib exec node index.js\n", false},
		{"pm2 ecosystem env", "ecosystem.config.js", "module.exports = {apps: [{script: 'index.js', env: {NODE_PATH: 'lib'}}]}\n", false},
		{"systemd unit", "deploy/app.service", "[Service]\nEnvironment=NODE_PATH=/srv/lib\nExecStart=/usr/bin/node /srv/index.js\n", false},
		{"set by first-party code before a child process", "src/spawn.js", "process.env.NODE_OPTIONS = '--require ./hook.js';\n", false},
		{"a README mention", "README.md", "Set NODE_PATH=src to run locally.\n", false},
		{"a manifest that sets none of them", "app.yaml", "runtime: nodejs20\nenv_variables:\n  NODE_ENV: production\n", true},
		{"a mention inside node_modules, which the walk does not enter", "node_modules/qs/package.json", `{"name":"qs","scripts":{"x":"NODE_PATH=a node"}}`, true},
		{"a mention inside site-packages, which the walk does not enter", "venv/lib/python3.12/site-packages/x/run.sh", "export NODE_PATH=lib\n", true},

		// NODE_OPTIONS, npm's node-options, and node flags that preload code or keep symlinks.
		{"NODE_OPTIONS in a Dockerfile", "Dockerfile", "FROM node:20\nENV NODE_OPTIONS=\"--require ./otel.js\"\n", false},
		{"NODE_OPTIONS from a variable", "deploy.sh", "export NODE_OPTIONS=\"$EXTRA\"\nnode server.js\n", false},
		{"NODE_OPTIONS carrying -r", "Procfile", "web: NODE_OPTIONS='-r ./apm.js' npm start\n", false},
		{"NODE_OPTIONS in a Kubernetes env list", "k8s/deployment.yaml", "env:\n  - name: NODE_OPTIONS\n    value: --import=./hook.mjs\n", false},
		{"node-options in .npmrc", ".npmrc", "node-options=--experimental-loader ./loader.mjs\n", false},
		{"--require in a package.json script", "package.json", `{"name":"app","scripts":{"start":"node --require ./apm.js index.js"}}`, false},
		{"--require= in a Procfile", "Procfile", "web: node --require=./apm.js server.js\n", false},
		{"--import in a Makefile", "Makefile", "run:\n\tnode --import ./register.mjs index.js\n", false},
		{"--loader in a pm2 ecosystem file", "ecosystem.config.js", "module.exports = {apps: [{script: 'index.js', node_args: '--loader ts-node/esm'}]}\n", false},
		{"--experimental-loader in a workflow", ".github/workflows/deploy.yml", "jobs:\n  run:\n    steps:\n      - run: node --experimental-loader ./l.mjs index.js\n", false},
		{"--preserve-symlinks in compose", "docker-compose.yml", "services:\n  web:\n    command: node --preserve-symlinks index.js\n", false},
		{"--preserve-symlinks-main in a script", "start.sh", "exec node --preserve-symlinks-main index.js\n", false},
		{"NODE_PRESERVE_SYMLINKS in an env file", ".env", "NODE_PRESERVE_SYMLINKS=1\n", false},

		// Resolver hooks first-party code or config installs.
		{"module-alias _moduleDirectories in package.json", "package.json", `{"name":"app","_moduleDirectories":["vendor_modules"]}`, false},
		{"module-alias _moduleAliases in package.json", "package.json", `{"name":"app","_moduleAliases":{"@lib":"vendor/lib"}}`, false},
		{"module-alias registered in code", "index.js", "require('module-alias/register');\n", false},
		{"app-module-path addPath", "index.js", "require('app-module-path').addPath(__dirname + '/vendor');\n", false},
		{"a Module._resolveFilename patch", "src/hook.js", "const Module = require('module');\nconst orig = Module._resolveFilename;\nModule._resolveFilename = function (r, ...a) { return orig.call(this, r, ...a); };\n", false},
		{"a Module._nodeModulePaths patch", "src/hook.js", "require('module')._nodeModulePaths = () => ['/opt/mods'];\n", false},

		// -r as a node argument.
		{"node -r in a Procfile", "Procfile", "web: node -r dotenv/config server.js\n", false},
		{"nodejs -r", "bin/start", "#!/bin/sh\nexec nodejs -r ./apm server.js\n", false},
		{"node.exe -r", "start.cmd", "node.exe -r ./apm index.js\r\n", false},
		{"nodemon -r in a package.json script", "package.json", `{"name":"app","scripts":{"dev":"nodemon -r dotenv/config index.js"}}`, false},
		{"-r after another node flag", "Procfile", "web: node --max-old-space-size=4096 -r ./apm server.js\n", false},
		{"-r in a Dockerfile exec-form array", "Dockerfile", "FROM node:20\nCMD [\"node\", \"-r\", \"dotenv/config\", \"server.js\"]\n", false},
		{"-r at the end of a node line", "run.sh", "node index.js -r\n", false},
		{"a node flag that changes neither", "Procfile", "web: node --max-old-space-size=4096 server.js\n", true},
		{"-r for another command", "build.sh", "cp -r public dist\n", true},
		{"-r after && on a node line", "build.sh", "node build.js && rm -r dist\n", false},
		{"-r after ; on a node line", "build.sh", "node build.js; cp -r out dist\n", false},
		{"-r on the line after node", "build.sh", "node build.js\ncp -r out dist\n", false},
		{"-r inside a longer word", "Procfile", "web: node server.js -rf\n", true},
		{"-r after a word that only contains node", "ops.sh", "kubectl get nodes -r\n", true},

		// Command lines are not parsed: node and a -r or -C anywhere in one file count.
		{"-r on a Dockerfile continuation line", "Dockerfile", "FROM node:20\nCMD node \\\n  -r zed/register server.js\n", false},
		{"-r in a Kubernetes args list", "k8s/deployment.yaml", "containers:\n  - name: web\n    command: [\"node\"]\n    args: [\"-r\", \"zed/register\", \"server.js\"]\n", false},
		{"-r in a compose block list", "docker-compose.yml", "services:\n  web:\n    command:\n      - node\n      - -r\n      - zed/register\n      - server.js\n", false},
		{"-r in a multi-line exec-form array", "Dockerfile", "FROM node:20\nCMD [\n  \"node\",\n  \"-r\",\n  \"zed/register\",\n  \"server.js\"\n]\n", false},
		{"-r= form", "Procfile", "web: node -r=./apm.js server.js\n", false},
		{"npx with -r", "package.json", `{"name":"app","scripts":{"test":"npx mocha -r ./setup.js"}}`, false},
		{"node -C", "Procfile", "web: node -C development server.js\n", false},
		{"--conditions", "start.sh", "exec node --conditions=development index.js\n", false},
		{"--experimental-policy", "start.sh", "exec node --experimental-policy=policy.json index.js\n", false},
		{"-C with no node in the file", "build.sh", "make -C sub all\n", true},

		// Resolver hooks reached without a first-party require('module').
		{"tsconfig-paths registered in code", "index.js", "require('tsconfig-paths/register');\n", false},
		{"tsconfig-paths in a ts-node tsconfig", "tsconfig.json", `{"ts-node":{"require":["tsconfig-paths/register"]}}`, false},
		{"registerHooks through getBuiltinModule", "index.js", "process.getBuiltinModule('module').registerHooks({ resolve });\n", false},
		{"registerHooks imported from node:module", "hooks.mjs", "import { registerHooks } from 'node:module';\nregisterHooks({ resolve });\n", false},
		{"getBuiltinModule('node:module') bound to a name", "index.js", "const m = process.getBuiltinModule(\"node:module\");\nm.findPackageJSON;\n", false},
		{"register imported from node:module", "hooks.mjs", "import { register } from 'node:module';\nregister('./hooks.mjs', import.meta.url);\n", false},
		{"module internals through a renamed binding", "src/hook.js", "const M = require('module');\nM._load = wrap(M._load);\n", false},
		{"module.constructor._load", "src/hook.js", "const load = module.constructor._load;\nmodule.constructor._load = (r, p, m) => load(r, p, m);\n", false},
		{"Module._extensions on a Module from module.constructor", "src/hook.js", "const Module = module.constructor;\nModule._extensions['.yml'] = loadYaml;\n", false},
		{"Module.prototype.require replaced", "src/hook.js", "const Module = module.constructor;\nModule.prototype.require = function (id) { return wrap(id); };\n", false},
		{"require.extensions", "src/hook.js", "require.extensions['.yml'] = loadYaml;\n", false},
		{"module.register", "hooks.mjs", "import module from 'node:module';\nmodule.register('./hooks.mjs', import.meta.url);\n", false},
		{"require reassigned", "src/boot.js", "require = wrap(require);\n", false},
		{"global.require assigned", "src/boot.js", "global.require = wrap(require);\n", false},
		{"a Module._findPath patch", "src/hook.js", "require('module')._findPath = find;\n", false},
		{"Module._initPaths called", "src/hook.js", "require('module')._initPaths();\n", false},
		{"require compared, not assigned", "src/boot.js", "if (require == null || module.require === undefined) {}\n", true},
		{"a require('module') that changes nothing", "src/list.js", "const { builtinModules } = require('module');\n", true},
		{"a register( call with no node:module load", "src/app.js", "register(user);\n", true},

		// Bundler resolution: what the bundle loads is what runs.
		{"webpack resolve.modules", "webpack.config.js", "module.exports = { resolve: { modules: ['vendor_modules', 'node_modules'] } };\n", false},
		{"webpack resolve.alias", "webpack.config.js", "module.exports = { resolve: { alias: { qs: path.resolve(__dirname, 'src/qs.js') } } };\n", false},
		{"vite alias", "vite.config.ts", "import { defineConfig } from 'vite';\nexport default defineConfig({ resolve: { alias: { qs: '/src/qs.js' } } });\n", false},
		{"rollup alias plugin", "rollup.config.mjs", "import alias from '@rollup/plugin-alias';\nexport default { plugins: [alias({ entries: [{ find: 'qs', replacement: './src/qs.js' }] })] };\n", false},
		{"esbuild alias", "build.mjs", "import * as esbuild from 'esbuild';\nawait esbuild.build({ entryPoints: ['index.js'], alias: { qs: './src/qs.js' } });\n", false},
		{"babel module-resolver", ".babelrc", `{"plugins":[["module-resolver",{"root":["./vendor"]}]]}`, false},
		{"resolve.alias set through a config chain", "config/chain.js", "config.resolve.alias.set('qs', './src/qs.js');\n", false},
		{"a webpack config with neither key", "webpack.config.js", "module.exports = { entry: './index.js', mode: 'production' };\n", true},
		{"an alias in a file that names no bundler", "src/routes.js", "const r = { alias: '/home' };\n", true},
		{"a package name that only contains modules", "package.json", `{"name":"app","devDependencies":{"webpack":"5","postcss-modules":"6"}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeProgram(t, map[string]string{"package-lock.json": lock, tc.file: tc.body})
			got := newLockClosures(dir).closureOf("", "qs")
			if bounded := got != nil; bounded != tc.bounded {
				t.Errorf("closureOf = %#v; bounded = %v, want %v", got, bounded, tc.bounded)
			}
		})
	}
}

// TestLockClosures_TreeVetoes: the lock bounds a reach only when it describes every package
// Node can resolve from the importing file. A lockfile, a workspaces root or a node_modules
// above the governing lock, a node_modules under its governance holding an entry it does not
// list at that key, another installer's lockfile, runtime or install state anywhere in the
// tree, a file: link above the lock, a symlink that leaves the tree or dangles, a symlinked
// node_modules, or a file the walk cannot read each leave the closure unbounded.
func TestLockClosures_TreeVetoes(t *testing.T) {
	const lock = `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/qs":{}}}`
	const lockSrcNM = `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/qs":{},"src/node_modules/util":{}}}`
	const lockAbove = `{"lockfileVersion":3,"packages":{"":{"name":"app","dependencies":{"shared":"file:../shared"}},"node_modules/qs":{},"node_modules/shared":{"link":true,"resolved":"../shared"},"../shared":{"name":"shared"}}}`
	const lockHook = `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/qs":{},"node_modules/tsconfig-paths":{"version":"4.2.0"}}}`
	const lockHookV1 = `{"lockfileVersion":1,"dependencies":{"tsconfig-paths":{"version":"4.2.0"}}}`
	const window, overlap = 1 << 20, 512
	cases := []struct {
		name    string
		from    string
		files   map[string]string
		setup   func(t *testing.T, dir string)
		bounded bool
	}{
		// readRegular follows symlinks; a package.json linked to a regular file outside the
		// tree is left to the walk, which vetoes every symlink that leaves it.
		{name: "a package.json above the lock symlinked to a regular file outside the tree", from: "app", files: map[string]string{
			"app/package-lock.json": lock, "app/main.js": "require('qs')\n"},
			setup: func(t *testing.T, dir string) {
				outside := filepath.Join(t.TempDir(), "package.json")
				treeWrite(t, outside, `{"name":"root"}`)
				treeSymlink(t, outside, filepath.Join(dir, "package.json"))
			}},
		{name: "the same package.json above the lock as a regular file", from: "app", bounded: true, files: map[string]string{
			"app/package-lock.json": lock, "app/main.js": "require('qs')\n", "package.json": `{"name":"root"}`}},

		// A node_modules above the governing lock is on every resolution path from it.
		{name: "a node_modules above the governing lock", from: "app", files: map[string]string{
			"app/package-lock.json": lock, "app/main.js": "require('qs')\n", "node_modules/zed/package.json": `{"name":"zed"}`}},
		{name: "a node_modules beside the governing lock that matches it", from: "app", bounded: true, files: map[string]string{
			"app/package-lock.json": lock, "app/main.js": "require('qs')\n", "app/node_modules/qs/package.json": `{"name":"qs"}`}},
		{name: "a node_modules in a sibling subtree under its own lock", from: "app", bounded: true, files: map[string]string{
			"app/package-lock.json": lock, "other/package-lock.json": lock, "other/node_modules/qs/package.json": `{"name":"qs"}`}},

		// Every node_modules under the lock's governance must match it, not only the ones the
		// lock names.
		{name: "a committed src/node_modules the lock does not list", files: map[string]string{
			"package-lock.json": lock, "src/node_modules/evil/index.js": ""}},
		{name: "a node_modules in a nested tool directory the lock does not list", from: "src", files: map[string]string{
			"package-lock.json": lock, "tools/gen/node_modules/x/index.js": ""}},
		{name: "a src/node_modules entry the lock lists at that key", bounded: true, files: map[string]string{
			"package-lock.json": lockSrcNM, "src/node_modules/util/index.js": ""}},

		// Another installer.
		{name: "yarn.lock beside the npm lock", files: map[string]string{"package-lock.json": lock, "yarn.lock": "# yarn lockfile v1\n"}},
		{name: "pnpm-lock.yaml beside the npm lock", files: map[string]string{"package-lock.json": lock, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"}},
		{name: "bun.lock beside the npm lock", files: map[string]string{"package-lock.json": lock, "bun.lock": "{}\n"}},
		{name: "a yarn.lock in another workspace", files: map[string]string{"package-lock.json": lock, "packages/x/yarn.lock": "# yarn lockfile v1\n"}},
		{name: "PnP runtime .pnp.cjs", files: map[string]string{"package-lock.json": lock, ".pnp.cjs": "#!/usr/bin/env node\n"}},
		{name: "PnP runtime .pnp.js", files: map[string]string{"package-lock.json": lock, ".pnp.js": "module.exports = {}\n"}},
		{name: "PnP ESM loader .pnp.loader.mjs", files: map[string]string{"package-lock.json": lock, ".pnp.loader.mjs": "export {}\n"}},
		{name: "pnpm's node_modules/.pnpm store", files: map[string]string{"package-lock.json": lock, "node_modules/.pnpm/lock.yaml": ""}},
		{name: "pnpm's node_modules/.modules.yaml", files: map[string]string{"package-lock.json": lock, "node_modules/.modules.yaml": ""}},
		{name: "yarn's node_modules/.yarn-state.yml", files: map[string]string{"package-lock.json": lock, "node_modules/.yarn-state.yml": ""}},
		{name: "PnP linker in .yarnrc.yml", files: map[string]string{"package-lock.json": lock, ".yarnrc.yml": "nodeLinker: pnp\n"}},
		{name: ".yarnrc.yml with the default linker", files: map[string]string{"package-lock.json": lock, ".yarnrc.yml": "yarnPath: .yarn/releases/yarn-4.1.0.cjs\n"}},
		{name: ".yarnrc.yml with the node_modules linker", bounded: true, files: map[string]string{"package-lock.json": lock, ".yarnrc.yml": "nodeLinker: node-modules\n"}},
		// An npm lockfile is parsed, not scanned: a hook package it lists is installed, not
		// launched. One that does not parse vetoes, and a package.json declaring the hook
		// package is scanned. yarn.lock and pnpm-lock.yaml veto as installer markers.
		{name: "a package-lock.json listing tsconfig-paths", bounded: true, files: map[string]string{"package-lock.json": lockHook}},
		{name: "an npm-shrinkwrap.json listing tsconfig-paths", bounded: true, files: map[string]string{"npm-shrinkwrap.json": lockHook}},
		{name: "a v1 package-lock.json listing tsconfig-paths", bounded: true, files: map[string]string{
			"package-lock.json": lock, "tools/package-lock.json": lockHookV1}},
		{name: "a corrupt package-lock.json", files: map[string]string{
			"package-lock.json": lock, "tools/package-lock.json": `{"lockfileVersion":3,"packages":{`}},
		{name: "a corrupt package-lock.json listing tsconfig-paths", files: map[string]string{
			"package-lock.json": lock, "tools/package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/tsconfig-paths":`}},
		{name: "a package-lock.json with no lockfileVersion", files: map[string]string{
			"package-lock.json": lock, "tools/package-lock.json": `{"name":"tools","packages":{}}`}},
		{name: "a package-lock.json with no packages or dependencies", files: map[string]string{
			"package-lock.json": lock, "tools/package-lock.json": `{"lockfileVersion":3}`}},
		{name: "a package.json dependency on tsconfig-paths", files: map[string]string{
			"package.json": `{"name":"app","dependencies":{"tsconfig-paths":"^4.2.0"}}`, "package-lock.json": lockHook}},
		{name: "a package.json devDependency on tsconfig-paths", files: map[string]string{
			"package.json": `{"name":"app","devDependencies":{"tsconfig-paths":"^4.2.0"}}`, "package-lock.json": lockHook}},
		{name: "a yarn.lock listing tsconfig-paths", files: map[string]string{
			"package-lock.json": lock, "yarn.lock": "tsconfig-paths@^4.2.0:\n  version \"4.2.0\"\n"}},
		{name: "a pnpm-lock.yaml listing tsconfig-paths", files: map[string]string{
			"package-lock.json": lock, "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  tsconfig-paths@4.2.0: {}\n"}},
		{name: "npm's own node_modules/.package-lock.json", bounded: true, files: map[string]string{"package-lock.json": lock, "node_modules/.package-lock.json": "{}"}},

		// A lockfile or a workspaces root above the governing lock: an install there puts a
		// node_modules on every resolution path, on disk or not, and npm installs a workspace
		// member from the root's lock.
		{name: "a lockfile above the governing lock with no node_modules on disk", from: "app", files: map[string]string{
			"package.json": `{"name":"root"}`, "package-lock.json": lock, "app/package.json": `{"name":"app"}`, "app/package-lock.json": lock}},
		{name: "a member lock under a workspaces root with no root lock", from: "packages/a", files: map[string]string{
			"package.json": `{"name":"root","workspaces":["packages/*"]}`, "packages/a/package-lock.json": lock}},
		{name: "a member lock under a workspaces root and its lock", from: "packages/a", files: map[string]string{
			"package.json": `{"name":"root","workspaces":{"packages":["packages/*"]}}`, "package-lock.json": lock, "packages/a/package-lock.json": lock}},
		{name: "an undecodable package.json above the governing lock", from: "app", files: map[string]string{
			"package.json": `{"name":`, "app/package-lock.json": lock}},
		{name: "a package.json without workspaces above the governing lock", from: "app", bounded: true, files: map[string]string{
			"package.json": `{"name":"root"}`, "app/package-lock.json": lock}},
		// A package.json declaring dependencies above the governing lock: npm installs it with
		// no lockfile.
		{name: "a package.json with dependencies above the governing lock and no root lock", from: "app", files: map[string]string{
			"package.json": `{"name":"root","dependencies":{"zed":"1.0.0"}}`, "app/package-lock.json": lock}},
		{name: "a package.json with devDependencies above the governing lock", from: "app", files: map[string]string{
			"package.json": `{"name":"root","devDependencies":{"zed":"1.0.0"}}`, "app/package-lock.json": lock}},
		{name: "a package.json with optionalDependencies above the governing lock", from: "app", files: map[string]string{
			"package.json": `{"name":"root","optionalDependencies":{"zed":"1.0.0"}}`, "app/package-lock.json": lock}},
		{name: "a package.json with peerDependencies above the governing lock", from: "app", files: map[string]string{
			"package.json": `{"name":"root","peerDependencies":{"zed":"1.0.0"}}`, "app/package-lock.json": lock}},
		{name: "a package.json with bundleDependencies above the governing lock", from: "app", files: map[string]string{
			"package.json": `{"name":"root","bundleDependencies":["zed"]}`, "app/package-lock.json": lock}},
		{name: "a package.json with bundledDependencies true above the governing lock", from: "app", files: map[string]string{
			"package.json": `{"name":"root","bundledDependencies":true}`, "app/package-lock.json": lock}},
		{name: "a package.json with empty dependency fields above the governing lock", from: "app", bounded: true, files: map[string]string{
			"package.json":          `{"name":"root","dependencies":{},"devDependencies":{},"optionalDependencies":null,"peerDependencies":{},"bundleDependencies":[],"bundledDependencies":false}`,
			"app/package-lock.json": lock}},
		{name: "a package.json with dependencies beside the governing lock", from: "app", bounded: true, files: map[string]string{
			"package.json": `{"name":"root"}`, "app/package.json": `{"name":"app","dependencies":{"qs":"6.0.0"}}`, "app/package-lock.json": lock}},
		{name: "a pnpm-workspace.yaml above the governing lock", from: "packages/a", files: map[string]string{
			"pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n", "packages/a/package-lock.json": lock}},
		{name: "a package.json with empty workspaces above the governing lock", from: "app", bounded: true, files: map[string]string{
			"package.json": `{"name":"root","workspaces":[]}`, "app/package-lock.json": lock}},
		{name: "a workspace member the root lock governs", from: "packages/a", bounded: true, files: map[string]string{
			"package.json": `{"name":"root","workspaces":["packages/*"]}`, "package-lock.json": lock, "packages/a/package.json": `{"name":"a"}`}},

		// tsconfig paths applied by a TypeScript runner.
		{name: "tsconfig paths and a tsx runner", files: map[string]string{"package-lock.json": lock,
			"tsconfig.json": `{"compilerOptions":{"paths":{"*":["vendor_modules/*"]}}}`, "Procfile": "web: tsx index.ts\n"}},
		{name: "a tsconfig base from a package and bun", files: map[string]string{"package-lock.json": lock,
			"tsconfig.json": `{"extends":"@tsconfig/node20/tsconfig.json"}`, "Procfile": "web: bun run index.ts\n"}},
		{name: "jsconfig baseUrl and ts-node", files: map[string]string{"package-lock.json": lock,
			"web/jsconfig.json": `{"compilerOptions":{"baseUrl":"src"}}`, "package.json": `{"name":"app","scripts":{"dev":"ts-node index.ts"}}`}},
		{name: "tsconfig paths with no runner", bounded: true, files: map[string]string{"package-lock.json": lock,
			"tsconfig.json": `{"compilerOptions":{"paths":{"*":["vendor_modules/*"]}}}`, "Procfile": "web: node dist/index.js\n"}},
		{name: "a tsx runner with a tsconfig that sets no paths", bounded: true, files: map[string]string{"package-lock.json": lock,
			"tsconfig.json": `{"extends":"./tsconfig.base.json","compilerOptions":{"strict":true}}`, "Procfile": "web: tsx index.ts\n"}},
		{name: "paths in a file that is not a tsconfig, with tsx", bounded: true, files: map[string]string{"package-lock.json": lock,
			"routes.json": `{"paths":{"/":"home"}}`, "Procfile": "web: tsx index.ts\n"}},

		{name: "a file: link to a directory above the lock", from: "app", files: map[string]string{
			"app/package-lock.json": lockAbove, "shared/package.json": `{"name":"shared"}`}},

		// Symlinks are never followed; one that leaves the tree or dangles fails closed.
		{name: "a symlink out of the build tree", files: map[string]string{"package-lock.json": lock},
			setup: func(t *testing.T, dir string) { treeSymlink(t, t.TempDir(), filepath.Join(dir, "vendor")) }},
		{name: "a dangling symlink", files: map[string]string{"package-lock.json": lock},
			setup: func(t *testing.T, dir string) { treeSymlink(t, filepath.Join(dir, "gone"), filepath.Join(dir, "cfg")) }},
		{name: "a symlinked node_modules inside the tree", files: map[string]string{"package-lock.json": lock, "store/qs/package.json": `{"name":"qs"}`},
			setup: func(t *testing.T, dir string) {
				treeSymlink(t, filepath.Join(dir, "store"), filepath.Join(dir, "node_modules"))
			}},
		{name: "an in-tree symlink to a file with no token", bounded: true, files: map[string]string{"package-lock.json": lock, "conf/base.yml": "port: 80\n"},
			setup: func(t *testing.T, dir string) {
				treeSymlink(t, filepath.Join(dir, "conf", "base.yml"), filepath.Join(dir, "app.yml"))
			}},
		{name: "an in-tree symlink is read through the link into node_modules", files: map[string]string{
			"package-lock.json": lock, "node_modules/.hooks/start": "NODE_PATH=lib node index.js\n"},
			setup: func(t *testing.T, dir string) {
				treeSymlink(t, filepath.Join(dir, "node_modules", ".hooks", "start"), filepath.Join(dir, "start"))
			}},

		// A symlinked directory is never followed. One inside the tree is read in full only when
		// the walk enters its target at the target's real path.
		{name: "an in-tree symlinked directory the walk reads at its target", bounded: true, files: map[string]string{
			"package-lock.json": lock, "conf/base.yml": "port: 80\n"},
			setup: func(t *testing.T, dir string) { treeSymlink(t, "conf", filepath.Join(dir, "cfg")) }},
		{name: "an in-tree symlinked directory into node_modules", files: map[string]string{
			"package-lock.json": lock, "node_modules/qs/package.json": `{"name":"qs"}`},
			setup: func(t *testing.T, dir string) {
				treeSymlink(t, filepath.Join(dir, "node_modules", "qs"), filepath.Join(dir, "vendored"))
			}},
		{name: "an in-tree symlinked directory into site-packages", files: map[string]string{
			"package-lock.json": lock, "py/lib/site-packages/x/a.txt": "port: 80\n"},
			setup: func(t *testing.T, dir string) {
				treeSymlink(t, filepath.Join(dir, "py", "lib", "site-packages", "x"), filepath.Join(dir, "x"))
			}},
		{name: "a symlinked directory cycle through an ancestor terminates", bounded: true, files: map[string]string{
			"package-lock.json": lock, "a/b/base.yml": "port: 80\n"},
			setup: func(t *testing.T, dir string) { treeSymlink(t, "..", filepath.Join(dir, "a", "b", "up")) }},
		{name: "a symlink loop", files: map[string]string{"package-lock.json": lock},
			setup: func(t *testing.T, dir string) {
				treeSymlink(t, "y", filepath.Join(dir, "x"))
				treeSymlink(t, "x", filepath.Join(dir, "y"))
			}},

		{name: "a file the walk cannot read", files: map[string]string{"package-lock.json": lock, "secret.env": "PORT=80\n"},
			setup: func(t *testing.T, dir string) {
				if os.Geteuid() == 0 {
					t.Skip("root reads any file")
				}
				p := filepath.Join(dir, "secret.env")
				if err := os.Chmod(p, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
			}},
		// The first read takes window+overlap bytes, so this token is split across two reads.
		{name: "a token straddling the read window", files: map[string]string{
			"package-lock.json": lock, "big.txt": strings.Repeat("x", window+overlap-5) + "\nNODE_PATH=lib\n"}},
		{name: "a token past the first read windows", files: map[string]string{
			"package-lock.json": lock, "big.txt": strings.Repeat("x", 3*window) + "\nNODE_PATH=lib\n"}},
		{name: "a large file with no token", bounded: true, files: map[string]string{
			"package-lock.json": lock, "big.txt": strings.Repeat("x", 3*window)}},
		{name: "a token under .git, which the walk enters", files: map[string]string{
			"package-lock.json": lock, ".git/hooks/post-merge": "#!/bin/sh\nNODE_PATH=lib node migrate.js\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeProgram(t, tc.files)
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			got := newLockClosures(dir).closureOf(tc.from, "qs")
			if bounded := got != nil; bounded != tc.bounded {
				t.Errorf("closureOf = %#v; bounded = %v, want %v", got, bounded, tc.bounded)
			}
		})
	}
}
