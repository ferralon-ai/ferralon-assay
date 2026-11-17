package jsanalysis

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// closurePkg is a read package at the top of node_modules with the given files beside a
// manifest naming index.js as main.
func closurePkg(name string, files map[string]string) *depPkg {
	m := map[string]string{
		"package.json": `{"name":"` + name + `","version":"1.0.0","main":"index.js"}`,
		"index.js":     "exports.run = function run() {};\n",
	}
	for k, v := range files {
		m[k] = v
	}
	return &depPkg{path: "node_modules/" + name, name: name, version: "1.0.0", files: m}
}

func closureOf(t *testing.T, f *depFixture, unread ...string) (plugin.CallGraphResult, *loadClosure) {
	t.Helper()
	kept := *f
	kept.pkgs = slices.DeleteFunc(slices.Clone(f.pkgs), func(p *depPkg) bool { return slices.Contains(unread, p.name) })
	cg, _, lc, err := callGraphWithClosure(context.Background(), f.dir, kept.memStore(), time.Minute)
	if err != nil {
		t.Fatalf("callGraphWithClosure: %v", err)
	}
	return cg, lc
}

// TestLoadClosure_Refutes: a package is refuted only when the closure is complete and nothing
// in it loads any installed copy. Every row asks about idle@1.0.0, which no first-party module
// loads; each withheld row is one way it may still run, or one way the closure may be missing
// code.
func TestLoadClosure_Refutes(t *testing.T) {
	const (
		app  = "const used = require('used');\nused.run();\n"
		purl = "pkg:npm/idle@1.0.0"
	)
	idle := func() *depPkg { return closurePkg("idle", nil) }
	used := func(src string) *depPkg { return closurePkg("used", map[string]string{"index.js": src}) }
	const (
		usedPlain    = "exports.run = function run() {};\n"
		computedLoad = "exports.run = function run(n) { return require(n); };\n"
	)
	usedDeclaring := func(field string) *depPkg {
		return closurePkg("used", map[string]string{"package.json": `{"name":"used","version":"1.0.0","main":"index.js","` + field + `":{"idle":"*"}}`, "index.js": computedLoad})
	}
	projectDeclaring := func(field string) string {
		return `{"name":"app","version":"1.0.0","` + field + `":{"idle":"*"}}`
	}
	scripts := func(line string) string {
		return `{"name":"app","version":"1.0.0","scripts":{"start":"` + line + `"}}`
	}
	// withheldBy names the veto a row must be withheld by; a row absent from it is withheld by
	// the package being loaded.
	withheldBy := map[string]string{
		"script runs a command no installed package provides":          "through a package runner",
		"unparsed .mts source":                                         "server.mts is not parsed",
		"unparsed .cts source":                                         "server.cts is not parsed",
		"unparsed .svelte source":                                      "App.svelte is not parsed",
		"unparsed .astro source":                                       "page.astro is not parsed",
		"source in a build output directory":                           "dist/server.js is not parsed",
		"source in a hidden directory":                                 ".config/hooks.js is not parsed",
		"node:test in loaded code":                                     "loads node:test, which can load or run other code",
		"wasi in loaded code":                                          "loads a built-in that can load or run other code",
		"sqlite in loaded code":                                        "loads a built-in that can load or run other code",
		"read package's lock-recorded command with no manifest target": "names no file in its package.json",
		"read package with an unreadable bin":                          "declares binaries the lane cannot read",
	}
	for _, tc := range []struct {
		name   string
		first  map[string]string
		pkgs   []*depPkg
		unread []string
		want   bool
		// assumed names the packages whose computed loads the closure bounds.
		assumed string
	}{
		{name: "nothing loads it", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(usedPlain), idle()}, want: true},
		{name: "first-party loads it", first: map[string]string{"index.js": app + "require('idle');\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "a loaded package loads it", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used("require('idle');\n" + usedPlain), idle()}},
		{name: "a loaded function loads it", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used("exports.run = function run() { return require('idle'); };\n"), idle()}},
		{name: "another loaded copy", first: map[string]string{"index.js": app}, pkgs: []*depPkg{
			used("require('idle');\n" + usedPlain), idle(),
			{path: "node_modules/used/node_modules/idle", name: "idle", version: "2.0.0", files: map[string]string{"package.json": `{"name":"idle","version":"2.0.0","main":"index.js"}`, "index.js": usedPlain}},
		}},

		// A computed load is bounded to the loading package, its declared dependencies and the
		// project's direct dependencies; a package outside the bound clears on that assumption.
		{name: "computed require in loaded code", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(computedLoad), idle()}, want: true, assumed: "used"},
		{name: "computed import in loaded code", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used("exports.run = function run(n) { return import(n); };\n"), idle()}, want: true, assumed: "used"},
		{name: "computed load, declared by the loading package", first: map[string]string{"index.js": app}, pkgs: []*depPkg{usedDeclaring("dependencies"), idle()}, assumed: "used"},
		{name: "computed load, peer of the loading package", first: map[string]string{"index.js": app}, pkgs: []*depPkg{usedDeclaring("peerDependencies"), idle()}, assumed: "used"},
		{name: "computed load, optional for the loading package", first: map[string]string{"index.js": app}, pkgs: []*depPkg{usedDeclaring("optionalDependencies"), idle()}, assumed: "used"},
		{name: "computed load, development dependency of the loading package", first: map[string]string{"index.js": app}, pkgs: []*depPkg{usedDeclaring("devDependencies"), idle()}, want: true, assumed: "used"},
		{name: "computed load, declared by the project", first: map[string]string{"index.js": app, "package.json": projectDeclaring("dependencies")}, pkgs: []*depPkg{used(computedLoad), idle()}, assumed: "used"},
		{name: "computed load, development dependency of the project", first: map[string]string{"index.js": app, "package.json": projectDeclaring("devDependencies")}, pkgs: []*depPkg{used(computedLoad), idle()}, assumed: "used"},
		{name: "computed load, declared by a workspace member", first: map[string]string{"index.js": app, "packages/a/package.json": projectDeclaring("dependencies")}, pkgs: []*depPkg{used(computedLoad), idle()}, assumed: "used"},
		{name: "project dependency with no computed load anywhere", first: map[string]string{"index.js": app, "package.json": projectDeclaring("dependencies")}, pkgs: []*depPkg{used(usedPlain), idle()}, want: true},
		{name: "computed load reaches a package that declares it", first: map[string]string{"index.js": app}, pkgs: []*depPkg{
			closurePkg("used", map[string]string{"package.json": `{"name":"used","version":"1.0.0","main":"index.js","dependencies":{"mid":"*"}}`, "index.js": computedLoad}),
			closurePkg("mid", map[string]string{"package.json": `{"name":"mid","version":"1.0.0","main":"index.js","dependencies":{"idle":"*"}}`}), idle()}, want: true, assumed: "used"},
		{name: "computed load reaches an unread package", first: map[string]string{"index.js": app}, pkgs: []*depPkg{
			closurePkg("used", map[string]string{"package.json": `{"name":"used","version":"1.0.0","main":"index.js","dependencies":{"mid":"*"}}`, "index.js": computedLoad}),
			closurePkg("mid", nil), idle()}, unread: []string{"mid"}},
		{name: "computed load reaches a module that loads it", first: map[string]string{"index.js": app}, pkgs: []*depPkg{
			closurePkg("used", map[string]string{"package.json": `{"name":"used","version":"1.0.0","main":"index.js","dependencies":{"mid":"*"}}`, "index.js": computedLoad}),
			closurePkg("mid", map[string]string{"lib/deep.js": "require('idle');\n"}), idle()}, assumed: "used"},
		{name: "computed load reaches another computed load", first: map[string]string{"index.js": app}, pkgs: []*depPkg{
			closurePkg("used", map[string]string{"package.json": `{"name":"used","version":"1.0.0","main":"index.js","dependencies":{"mid":"*"}}`, "index.js": computedLoad}),
			closurePkg("mid", map[string]string{"package.json": `{"name":"mid","version":"1.0.0","main":"index.js","dependencies":{"idle":"*"}}`, "lib/deep.js": computedLoad}), idle()}, assumed: "mid, used"},
		{name: "computed load reaches evaluated code", first: map[string]string{"index.js": app}, pkgs: []*depPkg{
			closurePkg("used", map[string]string{"package.json": `{"name":"used","version":"1.0.0","main":"index.js","dependencies":{"mid":"*"}}`, "index.js": computedLoad}),
			closurePkg("mid", map[string]string{"lib/deep.js": "module.exports = function (s) { return eval(s); };\n"}), idle()}},
		{name: "computed load in an unreached module of a loaded package", first: map[string]string{"index.js": app}, pkgs: []*depPkg{
			closurePkg("used", map[string]string{"package.json": `{"name":"used","version":"1.0.0","main":"index.js","dependencies":{"idle":"*"}}`, "lib/deep.js": computedLoad}), idle()}, want: true},
		{name: "computed load reaches its own unreached module", first: map[string]string{"index.js": app}, pkgs: []*depPkg{
			closurePkg("used", map[string]string{"index.js": computedLoad, "lib/deep.js": "require('idle');\n"}), idle()}, assumed: "used"},
		{name: "eval in loaded code", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used("exports.run = function run(s) { return eval(s); };\n"), idle()}},
		{name: "child process in loaded code", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used("const cp = require('child_process');\n" + usedPlain), idle()}},
		{name: "node: child process in loaded code", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used("const cp = require('node:child_process');\n" + usedPlain), idle()}},
		{name: "createRequire in loaded code", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used("const m = require('module');\n" + usedPlain), idle()}},
		{name: "other builtin in loaded code", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used("const fs = require('fs');\n" + usedPlain), idle()}, want: true},
		{name: "computed require in first-party code", first: map[string]string{"index.js": app + "module.exports = function (n) { return require(n); };\n"}, pkgs: []*depPkg{used(usedPlain), idle()}, want: true, assumed: "first-party code"},
		{name: "computed require in first-party code, declared by the project", first: map[string]string{"index.js": app + "module.exports = function (n) { return require(n); };\n", "package.json": projectDeclaring("optionalDependencies")}, pkgs: []*depPkg{used(usedPlain), idle()}, assumed: "first-party code"},
		{name: "child process in first-party code", first: map[string]string{"index.js": app + "require('child_process');\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},

		{name: "computed require outside the closure", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(usedPlain), idle(), closurePkg("other", map[string]string{"index.js": "exports.run = function run(n) { return require(n); };\n"})}, want: true},
		{name: "eval outside the closure", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(usedPlain), idle(), closurePkg("other", map[string]string{"index.js": "exports.run = function run(s) { return eval(s); };\n"})}, want: true},
		{name: "child process outside the closure", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(usedPlain), idle(), closurePkg("other", map[string]string{"index.js": "require('child_process');\n"})}, want: true},
		{name: "native addon outside the closure", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(usedPlain), idle(), closurePkg("other", map[string]string{"build/Release/other.node": "\x7fELF"})}, want: true},
		{name: "native addon in a loaded package", first: map[string]string{"index.js": app}, pkgs: []*depPkg{closurePkg("used", map[string]string{"build/Release/used.node": "\x7fELF"}), idle()}},
		{name: "unread package outside the closure", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(usedPlain), idle(), closurePkg("other", nil)}, unread: []string{"other"}, want: true},
		{name: "unread package loaded", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(usedPlain), idle()}, unread: []string{"used"}},
		{name: "itself unread and not loaded", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(usedPlain), idle()}, unread: []string{"idle"}, want: true},

		{name: "install script in a read package", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(usedPlain), idle(), closurePkg("other", map[string]string{"package.json": `{"name":"other","version":"1.0.0","scripts":{"postinstall":"node x.js"}}`})}},
		{name: "lock install script on an unread package", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(usedPlain), idle(), {path: "node_modules/other", name: "other", version: "1.0.0", files: map[string]string{"package.json": `{"name":"other","version":"1.0.0"}`}, lockInstallScript: true}}, unread: []string{"other"}},

		{name: "script names its binary", first: map[string]string{"index.js": app, "package.json": scripts("runner index.js")}, pkgs: []*depPkg{used(usedPlain),
			closurePkg("idle", map[string]string{"package.json": `{"name":"idle","version":"1.0.0","bin":{"runner":"cli.js"}}`, "cli.js": "module.exports = 1;\n"})}},
		{name: "script names its binary by path", first: map[string]string{"index.js": app, "package.json": scripts("./node_modules/.bin/idle index.js")}, pkgs: []*depPkg{used(usedPlain),
			closurePkg("idle", map[string]string{"package.json": `{"name":"idle","version":"1.0.0","bin":"cli.js"}`, "cli.js": "module.exports = 1;\n"})}},
		{name: "script names another binary", first: map[string]string{"index.js": app, "package.json": scripts("node index.js")}, pkgs: []*depPkg{used(usedPlain),
			closurePkg("idle", map[string]string{"package.json": `{"name":"idle","version":"1.0.0","bin":{"runner":"cli.js"}}`, "cli.js": "module.exports = 1;\n"})}, want: true},
		{name: "script binary loads it", first: map[string]string{"index.js": app, "package.json": scripts("tool --watch")}, pkgs: []*depPkg{used(usedPlain), idle(),
			closurePkg("tool", map[string]string{"package.json": `{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}`, "bin/tool.js": "require('idle');\n"})}},
		{name: "script binary loads something else", first: map[string]string{"index.js": app, "package.json": scripts("tool --watch")}, pkgs: []*depPkg{used(usedPlain), idle(),
			closurePkg("tool", map[string]string{"package.json": `{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}`, "bin/tool.js": "require('used');\n"})}, want: true},
		{name: "script binary is not a parsed file", first: map[string]string{"index.js": app, "package.json": scripts("tool --watch")}, pkgs: []*depPkg{used(usedPlain), idle(),
			closurePkg("tool", map[string]string{"package.json": `{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool"}}`, "bin/tool": "#!/usr/bin/env node\nrequire('idle');\n"})}},
		{name: "script preloads it", first: map[string]string{"index.js": app, "package.json": scripts("node -r idle/register index.js")}, pkgs: []*depPkg{used(usedPlain),
			closurePkg("idle", map[string]string{"register.js": "module.exports = 1;\n"})}},
		{name: "script preloads through NODE_OPTIONS", first: map[string]string{"index.js": app, "package.json": scripts("NODE_OPTIONS=--require=idle node index.js")}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "script runs a fetched command", first: map[string]string{"index.js": app, "package.json": scripts("npx --yes fetched@2 index.js")}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "script runs an installed command through npx", first: map[string]string{"index.js": app, "package.json": `{"name":"app","version":"1.0.0","dependencies":{"tool":"1.0.0"},"scripts":{"start":"npx tool"}}`}, pkgs: []*depPkg{used(usedPlain), idle(),
			closurePkg("tool", map[string]string{"package.json": `{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}`, "bin/tool.js": "require('used');\n"})}, want: true},
		{name: "script runs a command no installed package provides", first: map[string]string{"index.js": app, "package.json": scripts("pnpm exec absent")}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "a shell's own exec is not a package runner", first: map[string]string{"index.js": app, "start.sh": "#!/bin/sh\nexec node index.js\n"}, pkgs: []*depPkg{used(usedPlain), idle()}, want: true},

		// First-party sources the lane does not parse are roots it cannot follow.
		{name: "unparsed .mts source", first: map[string]string{"index.js": app, "server.mts": "import 'idle';\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "unparsed .cts source", first: map[string]string{"index.js": app, "server.cts": "require('idle');\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "unparsed .svelte source", first: map[string]string{"index.js": app, "App.svelte": "<script>import 'idle'</script>\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "unparsed .astro source", first: map[string]string{"index.js": app, "page.astro": "---\nimport 'idle';\n---\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "source in a build output directory", first: map[string]string{"index.js": app, "dist/server.js": "require('idle');\n", "package.json": scripts("node dist/server.js")}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "source in a hidden directory", first: map[string]string{"index.js": app, ".config/hooks.js": "require('idle');\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "declaration file is no source", first: map[string]string{"index.js": app, "types.d.mts": "export {};\n"}, pkgs: []*depPkg{used(usedPlain), idle()}, want: true},

		// Files other than package.json scripts start the project too.
		{name: "shell script a package.json script runs", first: map[string]string{"index.js": app, "start.sh": "exec node -r idle index.js\n", "package.json": scripts("sh ./start.sh")}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "interpreter-line file with no extension", first: map[string]string{"index.js": app, "bin/start": "#!/bin/sh\nnode -r idle index.js\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "Procfile preloads it", first: map[string]string{"index.js": app, "Procfile": "web: node -r idle index.js\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "Procfile that names nothing installed", first: map[string]string{"index.js": app, "Procfile": "web: node index.js\n"}, pkgs: []*depPkg{used(usedPlain), idle()}, want: true},
		{name: ".npmrc node-options preloads it", first: map[string]string{"index.js": app, ".npmrc": "node-options=--require idle\n", "package.json": scripts("node index.js")}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: ".env NODE_OPTIONS preloads it", first: map[string]string{"index.js": app, ".env.production": "NODE_OPTIONS=--require=idle\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "Dockerfile CMD preloads it", first: map[string]string{"index.js": app, "Dockerfile": "FROM node:22\nCMD [\"node\",\"-r\",\"idle/register\",\"index.js\"]\n"}, pkgs: []*depPkg{used(usedPlain),
			closurePkg("idle", map[string]string{"register.js": "module.exports = 1;\n"})}},
		{name: "compose command preloads it", first: map[string]string{"index.js": app, "deploy/docker-compose.prod.yml": "services:\n  web:\n    command: node -r idle index.js\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "process-manager config preloads it", first: map[string]string{"index.js": app, "ecosystem.config.js": "module.exports = { apps: [{ script: 'index.js', node_args: '-r idle' }] };\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "CI workflow runs its binary", first: map[string]string{"index.js": app, ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: node -r idle index.js\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "git hook runs its binary", first: map[string]string{"index.js": app, ".husky/pre-commit": "node -r idle index.js\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "package.json tool key names it", first: map[string]string{"index.js": app, "package.json": `{"name":"app","version":"1.0.0","nodemonConfig":{"exec":"node -r idle index.js"}}`}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "package.json dependency name is not a command", first: map[string]string{"index.js": app, "package.json": `{"name":"app","version":"1.0.0","dependencies":{"idle":"1.0.0","used":"1.0.0"}}`}, pkgs: []*depPkg{used(usedPlain), idle()}, want: true},

		// Built-ins that run a file no specifier names.
		{name: "node:test in loaded code", first: map[string]string{"index.js": app + "require('node:test').run({ files: ['node_modules/idle/index.js'] });\n"}, pkgs: []*depPkg{used(usedPlain), idle()}},
		{name: "wasi in loaded code", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used("const { WASI } = require('wasi');\n" + usedPlain), idle()}},
		{name: "sqlite in loaded code", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used("const sqlite = require('node:sqlite');\n" + usedPlain), idle()}},

		// A read package's commands come from bin, directories.bin and the lock's record.
		{name: "read package's directories.bin command", first: map[string]string{"index.js": app, "package.json": scripts("runner.js")}, pkgs: []*depPkg{used(usedPlain),
			closurePkg("idle", map[string]string{"package.json": `{"name":"idle","version":"1.0.0","main":"index.js","directories":{"bin":"bin"}}`, "bin/runner.js": "module.exports = 1;\n"})}},
		{name: "read package's lock-recorded command with no manifest target", first: map[string]string{"index.js": app, "package.json": scripts("runner")}, pkgs: []*depPkg{used(usedPlain),
			{path: "node_modules/idle", name: "idle", version: "1.0.0", lockBin: map[string]string{"runner": "bin/runner.js"}, files: map[string]string{"package.json": `{"name":"idle","version":"1.0.0","main":"index.js","directories":{"bin":"bin"}}`, "index.js": usedPlain, "bin/runner": "#!/usr/bin/env node\n"}}}},
		{name: "read package with an unreadable bin", first: map[string]string{"index.js": app}, pkgs: []*depPkg{used(usedPlain),
			closurePkg("idle", map[string]string{"package.json": `{"name":"idle","version":"1.0.0","main":"index.js","bin":["cli.js"]}`})}},
		{name: "unread package's binary named by a script", first: map[string]string{"index.js": app, "package.json": scripts("runner")}, pkgs: []*depPkg{used(usedPlain),
			{path: "node_modules/idle", name: "idle", version: "1.0.0", lockBin: map[string]string{"runner": "cli.js"}, files: map[string]string{"package.json": `{"name":"idle","version":"1.0.0"}`}}}, unread: []string{"idle"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDepFixture(t, tc.first, tc.pkgs...)
			_, lc := closureOf(t, f, tc.unread...)
			if got := lc.refutes(purl); got != tc.want {
				t.Errorf("refutes(%s) = %v, want %v; closure %+v", purl, got, tc.want, lc)
			}
			var want []string
			if tc.assumed != "" {
				want = []string{"computed module loads in " + tc.assumed + " are assumed to resolve only to those packages' declared dependencies and the project's direct dependencies"}
			}
			if lc.Complete && !slices.Equal(lc.Assumptions, want) {
				t.Errorf("assumptions = %q, want %q", lc.Assumptions, want)
			}
			if want, ok := withheldBy[tc.name]; ok && !slices.ContainsFunc(lc.Vetoes, func(v string) bool { return strings.Contains(v, want) }) {
				t.Errorf("vetoes = %q, want one containing %q (loaded %q)", lc.Vetoes, want, lc.Loaded)
			}
			if lc.refutes("pkg:npm/used@1.0.0") {
				t.Errorf("a package first-party code loads is refuted; closure %+v", lc)
			}
			if lc.refutes("pkg:npm/absent@1.0.0") {
				t.Errorf("a package no lockfile places is refuted; closure %+v", lc)
			}
		})
	}
}

// TestLoadClosure_UnenumerableLayout: a lock that does not record what each package installs
// and runs (npm v1, pnpm, yarn classic) cannot rule out an unread package's install script or
// binary, so nothing is refuted under it.
func TestLoadClosure_UnenumerableLayout(t *testing.T) {
	integrity := sri([]byte("dep"))
	for name, files := range map[string]map[string]string{
		"npm_v3_control": {"package-lock.json": `{"name":"app","lockfileVersion":3,"requires":true,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"dep":"1.0.0"}},"node_modules/dep":{"version":"1.0.0","resolved":"https://registry.npmjs.org/dep/-/dep-1.0.0.tgz","integrity":"` + integrity + `"}}}`},
		"npm_v1":         {"package-lock.json": `{"name":"app","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{"dep":{"version":"1.0.0","resolved":"https://registry.npmjs.org/dep/-/dep-1.0.0.tgz","integrity":"` + integrity + `"}}}`},
		"yarn_classic":   {"yarn.lock": "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\ndep@1.0.0:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/dep/-/dep-1.0.0.tgz\"\n  integrity " + integrity + "\n"},
		"no_lockfile":    {},
	} {
		t.Run(name, func(t *testing.T) {
			files["package.json"] = `{"name":"app","version":"1.0.0","dependencies":{"dep":"1.0.0"}}`
			files["index.js"] = guardIdle
			_, _, lc, err := callGraphWithClosure(context.Background(), writeProgram(t, files), artifactcache.NewDeclaredAbsentStore(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := lc.refutes(guardPURL), name == "npm_v3_control"; got != want {
				t.Errorf("refutes = %v, want %v; closure %+v", got, want, lc)
			}
		})
	}
}

// TestLoadClosure_NPMOrigin: the admitted package is matched by name, never by version, in the
// spelling the inventory mints.
func TestLoadClosure_NPMOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/lodash@4.17.20":               "pkg:npm/lodash",
		"pkg:npm/%40babel/core@7.0.0":          "pkg:npm/%40babel/core",
		"pkg:npm/@babel/core@7.0.0":            "pkg:npm/%40babel/core",
		"pkg:npm/lodash@4.17.20?vcs_url=x#sub": "pkg:npm/lodash",
		"pkg:npm/lodash":                       "pkg:npm/lodash",
		"pkg:golang/lodash@1.0.0":              "",
		"pkg:npm/":                             "",
		"":                                     "",
	} {
		got, ok := npmOrigin(in)
		if got != want || ok != (want != "") {
			t.Errorf("npmOrigin(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if o, _ := npmOrigin(makePURL("@Scope/Name", "1.0.0")); o != originPURL("@Scope/Name") {
		t.Errorf("an inventory PURL does not round-trip to its origin: %q vs %q", o, originPURL("@Scope/Name"))
	}
}

// TestLoadClosure_Reachability: a symbol of a package nothing loads comes back refuted with no
// ingress limit of its own, the limits that remain are bounded to the code that loads, and a
// request that names no package is never refuted.
func TestLoadClosure_Reachability(t *testing.T) {
	f := newDepFixture(t, map[string]string{"index.js": "const used = require('used');\nused.make().go();\n"},
		closurePkg("used", map[string]string{"index.js": "exports.make = function make() { return { go() {} }; };\n"}),
		closurePkg("idle", map[string]string{"index.js": "exports.bad = function bad() {};\n"}),
	)
	cache := f.diskCache(t)
	const sink = "npm:idle@1.0.0#bad"
	run := func(pkg string) plugin.ReachabilityResult {
		t.Helper()
		res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: f.dir, Symbols: []string{sink}, Package: pkg, DependencyCache: cache})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	res := run("pkg:npm/idle@1.0.0")
	if res.Refutation == nil || res.Refutation.Basis != plugin.RefutationPackageNotLoaded || res.Refutation.Package != "pkg:npm/idle@1.0.0" || res.Refutation.Detail == "" {
		t.Fatalf("want a package_not_loaded refutation on the admitted package; got %+v", res.Refutation)
	}
	if slices.Contains(res.Partiality.Reasons, plugin.PartialReasonNoIngress) {
		t.Errorf("a refuted symbol declares no ingress limit; got %+v", res.Partiality)
	}
	for _, r := range []string{plugin.PartialReasonUninspectablePackage, plugin.PartialReasonUnlistedSites} {
		if slices.Contains(res.Partiality.Reasons, r) {
			t.Errorf("%s is run-wide under a complete closure; got %+v", r, res.Partiality)
		}
	}
	bounded := false
	for _, s := range res.Partiality.Scoped {
		if s.Reason != plugin.PartialReasonUnlistedSites {
			continue
		}
		bounded = true
		if !slices.Equal(s.Targets, []string{"pkg:npm/used", ""}) {
			t.Errorf("unlisted_sites targets = %q, want the loaded package and first-party code", s.Targets)
		}
	}
	if !bounded {
		t.Errorf("the declined call keeps a bounded unlisted_sites limit; got %+v", res.Partiality)
	}

	for _, pkg := range []string{"", "pkg:npm/used@1.0.0", "pkg:npm/absent@1.0.0"} {
		res := run(pkg)
		if res.Refutation != nil {
			t.Errorf("Package %q: refuted %+v", pkg, res.Refutation)
		}
		if !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonNoIngress) {
			t.Errorf("Package %q: an unreached symbol that is not refuted keeps its ingress limit; got %+v", pkg, res.Partiality)
		}
	}

	bare, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: f.dir, Symbols: []string{sink}, Package: "pkg:npm/idle@1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if bare.Refutation != nil {
		t.Errorf("with no dependency code read nothing says what loads; refuted %+v", bare.Refutation)
	}
}

// TestLoadClosure_ScriptRoots: each script word that names an installed binary, or resolves as
// a module specifier, is one root, selected by its file inside the package. A script line is
// not interpreted, so a word that is both roots both.
func TestLoadClosure_ScriptRoots(t *testing.T) {
	f := newDepFixture(t, map[string]string{
		"index.js":     guardIdle,
		"package.json": `{"name":"app","version":"1.0.0","scripts":{"start":"tool --serve","dev":"node -r hook/register index.js && tool"}}`,
	},
		closurePkg("tool", map[string]string{"package.json": `{"name":"tool","version":"1.0.0","bin":{"tool":"./bin/tool.js"}}`, "bin/tool.js": "module.exports = 1;\n"}),
		closurePkg("hook", map[string]string{"register.js": "module.exports = 1;\n"}),
	)
	_, lc := closureOf(t, f)
	var got []string
	for _, r := range lc.Roots {
		got = append(got, strings.Join([]string{r.Lane, r.Kind, r.Selector, r.Name, r.Origin}, " "))
	}
	want := []string{
		"js script npm:hook/register.js hook/register package.json#scripts.dev",
		"js bin npm:tool/bin/tool.js tool package.json#scripts.dev",
		"js bin npm:tool/bin/tool.js tool package.json#scripts.start",
		"js script npm:tool/index.js tool package.json#scripts.dev",
		"js script npm:tool/index.js tool package.json#scripts.start",
	}
	if !slices.Equal(got, want) {
		t.Errorf("roots:\n got %q\nwant %q", got, want)
	}
	if !lc.Complete || !slices.Equal(lc.Loaded, []string{"pkg:npm/hook", "pkg:npm/tool"}) {
		t.Errorf("want a complete closure loading hook and tool; got %+v", lc)
	}
}
