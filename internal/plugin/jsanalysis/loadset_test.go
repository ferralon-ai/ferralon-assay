package jsanalysis

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// lockPkg is one npm v3 `packages` entry for a test lockfile.
type lockPkg struct {
	Version  string            `json:"version,omitempty"`
	Dev      bool              `json:"dev,omitempty"`
	Deps     map[string]string `json:"dependencies,omitempty"`
	DevDeps  map[string]string `json:"devDependencies,omitempty"`
	Optional map[string]string `json:"optionalDependencies,omitempty"`
	Peers    map[string]string `json:"peerDependencies,omitempty"`
	Bin      map[string]string `json:"bin,omitempty"`
	Link     bool              `json:"link,omitempty"`
	Resolved string            `json:"resolved,omitempty"`
}

// npmLockJSON builds a v3 lockfile whose root entry depends on every top-level package: a
// dev-marked one under devDependencies, any other under dependencies.
func npmLockJSON(t *testing.T, pkgs map[string]lockPkg) string {
	t.Helper()
	top, devTop := map[string]string{}, map[string]string{}
	all := map[string]lockPkg{}
	for k, v := range pkgs {
		all[k] = v
		if name, ok := npmTopSegment(k); ok {
			if v.Dev {
				devTop[name] = "*"
			} else {
				top[name] = "*"
			}
		}
	}
	all[""] = lockPkg{Version: "1.0.0", Deps: top, DevDeps: devTop}
	data, err := json.Marshal(map[string]any{"name": "app", "lockfileVersion": 3, "packages": all})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func dep(names ...string) map[string]string {
	m := map[string]string{}
	for _, n := range names {
		m[n] = "*"
	}
	return m
}

func TestLoadSet(t *testing.T) {
	type check struct {
		pkg, version string
		refuted      bool
		detail       string // substring the refutation detail must contain
	}
	cases := []struct {
		name         string
		files        func(t *testing.T) map[string]string
		complete     bool
		loadedPaths  []string
		unloaded     []string
		checks       []check
		scopedLoader string
	}{
		{
			name: "nested instance loaded, hoisted copy of the same name is not",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","dependencies":{"a":"*"},"devDependencies":{"c":"*"}}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/a":                {Version: "1.0.0", Deps: dep("b")},
						"node_modules/a/node_modules/b": {Version: "2.0.0"},
						"node_modules/b":                {Version: "1.0.0", Dev: true},
						"node_modules/c":                {Version: "1.0.0", Dev: true, Deps: dep("b")},
					}),
					"index.js": `const a = require('a');`,
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/a", "node_modules/a/node_modules/b"},
			unloaded:    []string{"node_modules/b", "node_modules/c"},
			checks: []check{
				{pkg: "b", version: "1.0.0", refuted: false}, // another instance of b is loaded
				{pkg: "c", version: "1.0.0", refuted: true, detail: "not reachable from any first-party root"},
			},
		},
		{
			name: "string literal in runtime source naming an installed package is a root",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app"}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/fancy-plugin": {Version: "1.0.0"},
						"node_modules/unused":       {Version: "1.0.0", Dev: true},
					}),
					"server.js": "const plugins = ['fancy-plugin'];\nmodule.exports = plugins;\n",
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/fancy-plugin"},
			checks: []check{
				{pkg: "fancy-plugin", version: "1.0.0", refuted: false},
				{pkg: "unused", version: "1.0.0", refuted: true},
			},
		},
		{
			name: "package reachable only from a script bin is not loaded",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","scripts":{"dev":"nodemon server.js","start":"node server.js"}}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/nodemon":  {Version: "2.0.0", Dev: true, Deps: dep("chokidar"), Bin: map[string]string{"nodemon": "bin/nodemon.js"}},
						"node_modules/chokidar": {Version: "3.0.0", Dev: true},
						"node_modules/a":        {Version: "1.0.0"},
					}),
					"server.js": `require('a');`,
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/a"},
			unloaded:    []string{"node_modules/nodemon", "node_modules/chokidar"},
			checks: []check{
				{pkg: "nodemon", version: "2.0.0", refuted: true, detail: "only reachable from dev tooling: nodemon (scripts.dev)"},
				{pkg: "chokidar", version: "3.0.0", refuted: true, detail: "only reachable from dev tooling: nodemon (scripts.dev)"},
				{pkg: "chokidar", version: "3.0.0", refuted: true, detail: "assumes dev/tooling groups are not installed at runtime"},
				{pkg: "chokidar", version: "9.9.9", refuted: false}, // not installed at the admitted version
			},
		},
		{
			name: "peer dependency of a loaded package is loaded",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app"}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/plugin-x": {Version: "1.0.0", Peers: dep("host-lib")},
						"node_modules/host-lib": {Version: "4.0.0"},
					}),
					"index.mjs": `import x from 'plugin-x';`,
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/plugin-x", "node_modules/host-lib"},
			checks:      []check{{pkg: "host-lib", version: "4.0.0", refuted: false}},
		},
		{
			name: "computed require leaves the load set incomplete",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app"}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/a":      {Version: "1.0.0"},
						"node_modules/unused": {Version: "1.0.0"},
					}),
					"index.js": "require('a');\nfunction load(n) { return require(n); }\n",
				}
			},
			complete:    false,
			loadedPaths: []string{"node_modules/a"},
			checks:      []check{{pkg: "unused", version: "1.0.0", refuted: false}},
		},
		{
			name: "enumerating loader adds its targets",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app"}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/express":       {Version: "4.0.0"},
						"node_modules/pug":           {Version: "3.0.0", Deps: dep("jstransformer")},
						"node_modules/jstransformer": {Version: "1.0.0"},
						"node_modules/unused":        {Version: "1.0.0", Dev: true},
					}),
					"app.js": `const express = require('express');`,
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/express", "node_modules/pug", "node_modules/jstransformer"},
			checks: []check{
				{pkg: "pug", version: "3.0.0", refuted: false},
				{pkg: "unused", version: "1.0.0", refuted: true, detail: "loaders expanded: express"},
			},
		},
		{
			name: "unbounded enumerating loader blocks every refutation",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app"}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/module-alias": {Version: "2.0.0"},
						"node_modules/unused":       {Version: "1.0.0", Dev: true},
					}),
					"index.js": `require('module-alias/register');`,
				}
			},
			complete:     true,
			loadedPaths:  []string{"node_modules/module-alias"},
			checks:       []check{{pkg: "unused", version: "1.0.0", refuted: false}},
			scopedLoader: "pkg:npm/module-alias",
		},
		{
			name: "dev-flagged package required at runtime is loaded",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","devDependencies":{"d":"*"}}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/d": {Version: "1.0.0", Dev: true},
					}),
					"src/index.ts": `import { d } from "d";`,
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/d"},
			checks:      []check{{pkg: "d", version: "1.0.0", refuted: false}},
		},
		{
			name: "no lockfile never refutes",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","dependencies":{"a":"1.0.0"}}`,
					"index.js":     `require('a');`,
				}
			},
			complete: false,
			checks:   []check{{pkg: "a", version: "1.0.0", refuted: false}},
		},
		{
			name: "test files and dev configs are dev tooling, build injectors are loaded",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app"}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/supertest":           {Version: "6.0.0", Dev: true},
						"node_modules/eslint-plugin-x":     {Version: "1.0.0"},
						"node_modules/@babel/core":         {Version: "7.0.0"},
						"node_modules/regenerator-runtime": {Version: "0.13.0"},
						"node_modules/a":                   {Version: "1.0.0"},
					}),
					"index.js":         `require('a');`,
					"test/app.test.js": `const request = require('supertest');`,
					".eslintrc.js":     `module.exports = { plugins: ['eslint-plugin-x'] };`,
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/a", "node_modules/regenerator-runtime"},
			unloaded:    []string{"node_modules/supertest", "node_modules/eslint-plugin-x", "node_modules/@babel/core"},
			checks: []check{
				{pkg: "supertest", version: "6.0.0", refuted: true, detail: "only reachable from dev tooling: test/app.test.js"},
				{pkg: "regenerator-runtime", version: "0.13.0", refuted: false},
			},
		},
		{
			name: "yarn root with node_modules installed uses the disk tree",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json":                `{"name":"app"}`,
					"yarn.lock":                   "# yarn lockfile v1\n",
					"node_modules/a/package.json": `{"name":"a","version":"1.0.0","dependencies":{"b":"^2"}}`,
					"node_modules/a/node_modules/b/package.json": `{"name":"b","version":"2.0.0"}`,
					"node_modules/b/package.json":                `{"name":"b","version":"1.0.0"}`,
					"node_modules/c/package.json":                `{"name":"c","version":"1.0.0"}`,
					"index.js":                                   `require('a');`,
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/a", "node_modules/a/node_modules/b"},
			unloaded:    []string{"node_modules/b", "node_modules/c"},
			// yarn.lock carries no dev markers, so runtime cannot be told from dev.
			checks: []check{{pkg: "c", version: "1.0.0", refuted: false}},
		},
		{
			name: "yarn root without node_modules never refutes",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app"}`,
					"yarn.lock":    "# yarn lockfile v1\n",
					"index.js":     `require('a');`,
				}
			},
			complete: false,
			checks:   []check{{pkg: "c", version: "1.0.0", refuted: false}},
		},
		{
			name: "workspace link resolves to first-party code",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","workspaces":["packages/*"]}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"packages/lib":     {Version: "1.0.0", Deps: dep("b")},
						"node_modules/lib": {Link: true, Resolved: "packages/lib"},
						"node_modules/b":   {Version: "1.0.0"},
						"node_modules/c":   {Version: "1.0.0", Dev: true},
					}),
					"packages/lib/package.json": `{"name":"lib","dependencies":{"b":"*"}}`,
					"packages/lib/index.js":     `module.exports = require('b');`,
					"index.js":                  `require('lib');`,
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/b"},
			unloaded:    []string{"node_modules/c"},
			checks:      []check{{pkg: "c", version: "1.0.0", refuted: true}},
		},
		{
			name: "runtime-installed package no code loads never refutes",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","dependencies":{"a":"*","b":"*"},"optionalDependencies":{"o":"*"}}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/a": {Version: "1.0.0"},
						"node_modules/b": {Version: "1.0.0", Deps: dep("t")},
						"node_modules/t": {Version: "1.0.0"},
						"node_modules/o": {Version: "1.0.0"},
					}),
					"index.js": `require('a');`,
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/a"},
			unloaded:    []string{"node_modules/b", "node_modules/t", "node_modules/o"},
			checks: []check{
				{pkg: "b", version: "1.0.0", refuted: false},
				{pkg: "t", version: "1.0.0", refuted: false}, // transitive runtime dependency
				{pkg: "o", version: "1.0.0", refuted: false}, // optional dependencies install in production
			},
		},
		{
			name: "dev marker contradicted by a runtime manifest dependency never refutes",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","dependencies":{"a":"*","x":"*"}}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/a": {Version: "1.0.0"},
						"node_modules/x": {Version: "1.0.0", Dev: true}, // stale lockfile
					}),
					"index.js": `require('a');`,
				}
			},
			complete: true,
			unloaded: []string{"node_modules/x"},
			checks:   []check{{pkg: "x", version: "1.0.0", refuted: false}},
		},
		{
			name: "dependency soft import of a dev-only package is not a load",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","dependencies":{"debug":"*"},"devDependencies":{"supports-color":"*"}}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/debug":          {Version: "2.6.9", Deps: dep("ms")},
						"node_modules/ms":             {Version: "2.0.0"},
						"node_modules/supports-color": {Version: "5.5.0", Dev: true},
					}),
					"index.js": `const debug = require('debug')('app');`,
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/debug", "node_modules/ms"},
			unloaded:    []string{"node_modules/supports-color"},
			checks:      []check{{pkg: "supports-color", version: "5.5.0", refuted: true}},
		},
		{
			name: "v1 lockfile dev markers apply to the installed tree, alongside a yarn.lock",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","dependencies":{"a":"*"},"devDependencies":{"tool":"*"}}`,
					"yarn.lock":    "# yarn lockfile v1\n",
					"package-lock.json": `{"name":"app","lockfileVersion":1,"dependencies":{
						"a":{"version":"1.0.0"},
						"tool":{"version":"2.0.0","dev":true,"dependencies":{"glob":{"version":"7.0.0","dev":true}}},
						"stale":{"version":"1.0.0","dev":true}}}`,
					"node_modules/a/package.json":                      `{"name":"a","version":"1.0.0"}`,
					"node_modules/tool/package.json":                   `{"name":"tool","version":"2.0.0","dependencies":{"glob":"^7"}}`,
					"node_modules/tool/node_modules/glob/package.json": `{"name":"glob","version":"7.0.0"}`,
					"node_modules/stale/package.json":                  `{"name":"stale","version":"1.1.0"}`,
					"index.js":                                         `require('a');`,
				}
			},
			complete:    true,
			loadedPaths: []string{"node_modules/a"},
			unloaded:    []string{"node_modules/tool", "node_modules/tool/node_modules/glob", "node_modules/stale"},
			checks: []check{
				{pkg: "glob", version: "7.0.0", refuted: true, detail: "outside the runtime install closure"},
				{pkg: "stale", version: "1.1.0", refuted: false}, // installed version differs from the marked entry
			},
		},
		{
			name: "install closure resolving outside the build dir withholds every refutation",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","dependencies":{"a":"*","ext":"*"}}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/a":    {Version: "1.0.0"},
						"node_modules/ext":  {Link: true, Resolved: "../ext"},
						"node_modules/tool": {Version: "1.0.0", Dev: true},
					}),
					"index.js": `require('a');`,
				}
			},
			complete: true,
			unloaded: []string{"node_modules/tool"},
			checks:   []check{{pkg: "tool", version: "1.0.0", refuted: false}},
		},
		{
			name: "deploy-path install that keeps dev dependencies withholds every refutation",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","dependencies":{"a":"*"}}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/a":    {Version: "1.0.0"},
						"node_modules/tool": {Version: "1.0.0", Dev: true},
					}),
					"Dockerfile": "FROM node:20\nCOPY . .\nRUN npm ci\nCMD [\"node\", \"index.js\"]\n",
					"index.js":   `require('a');`,
				}
			},
			complete: true,
			unloaded: []string{"node_modules/tool"},
			checks:   []check{{pkg: "tool", version: "1.0.0", refuted: false}},
		},
		{
			name: "deploy-path production install keeps refutations",
			files: func(t *testing.T) map[string]string {
				return map[string]string{
					"package.json": `{"name":"app","dependencies":{"a":"*"}}`,
					"package-lock.json": npmLockJSON(t, map[string]lockPkg{
						"node_modules/a":    {Version: "1.0.0"},
						"node_modules/tool": {Version: "1.0.0", Dev: true},
					}),
					"Dockerfile":                 "FROM node:20\nCOPY . .\nRUN npm ci --omit=dev\n",
					".github/workflows/test.yml": "name: test\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n      - run: npm test\n",
					"test/setup.sh":              "npm install\n",
					"index.js":                   `require('a');`,
				}
			},
			complete: true,
			checks:   []check{{pkg: "tool", version: "1.0.0", refuted: true}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files(t))
			ls := computeLoadSet(dir)
			if ls.complete != tc.complete {
				t.Fatalf("complete = %v, want %v (gaps %q)", ls.complete, tc.complete, ls.gaps)
			}
			for _, p := range tc.loadedPaths {
				if !ls.loaded[p] {
					t.Errorf("%s not loaded; loaded=%v", p, ls.loaded)
				}
			}
			for _, p := range tc.unloaded {
				if ls.loaded[p] {
					t.Errorf("%s loaded, want not loaded", p)
				}
			}
			if tc.scopedLoader != "" {
				if len(ls.scoped) != 1 || ls.scoped[0].Package != tc.scopedLoader || ls.scoped[0].Targets != nil {
					t.Errorf("scoped = %+v, want one unbounded reason for %s", ls.scoped, tc.scopedLoader)
				}
			}
			for _, c := range tc.checks {
				ref := ls.refute(c.pkg, c.version)
				if (ref != nil) != c.refuted {
					t.Errorf("refute(%s@%s) = %+v, want refuted=%v", c.pkg, c.version, ref, c.refuted)
					continue
				}
				if ref == nil {
					continue
				}
				if ref.Basis != plugin.RefutationPackageNotLoaded || ref.Package != "pkg:npm/"+c.pkg {
					t.Errorf("refutation = %+v", ref)
				}
				if !strings.Contains(ref.Detail, c.detail) {
					t.Errorf("detail %q lacks %q", ref.Detail, c.detail)
				}
			}
		})
	}
}

func TestReachabilityEmitsPackageNotLoaded(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"package.json": `{"name":"app","scripts":{"dev":"nodemon index.js"}}`,
		"package-lock.json": npmLockJSON(t, map[string]lockPkg{
			"node_modules/nodemon":  {Version: "2.0.0", Dev: true, Deps: dep("semver"), Bin: map[string]string{"nodemon": "bin/nodemon.js"}},
			"node_modules/semver":   {Version: "5.7.1", Dev: true},
			"node_modules/left-pad": {Version: "1.3.0"},
		}),
		"index.js": "const pad = require('left-pad');\nmodule.exports = () => pad('x', 2);\n",
	})
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Package: "pkg:npm/semver@5.7.1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Refutation == nil || res.Refutation.Package != "pkg:npm/semver" ||
		!strings.Contains(res.Refutation.Detail, "only reachable from dev tooling: nodemon (scripts.dev)") {
		t.Fatalf("refutation = %+v", res.Refutation)
	}
	res, err = Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Package: "pkg:npm/left-pad@1.3.0"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Refutation != nil {
		t.Fatalf("loaded package refuted: %+v", res.Refutation)
	}
	res, err = Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Refutation != nil {
		t.Fatalf("refutation without a requested package: %+v", res.Refutation)
	}
}

func TestNpmPackageRef(t *testing.T) {
	cases := []struct {
		purl, name, version string
		ok                  bool
	}{
		{"pkg:npm/lodash@4.17.20", "lodash", "4.17.20", true},
		{"pkg:npm/%40babel/core@7.1.0", "@babel/core", "7.1.0", true},
		{"pkg:npm/@babel/core@7.1.0?foo=bar", "@babel/core", "7.1.0", true},
		{"pkg:npm/lodash", "", "", false},
		{"pkg:npm/%40babel/core", "", "", false},
		{"pkg:pypi/requests@2.0.0", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		n, v, ok := npmPackageRef(c.purl)
		if n != c.name || v != c.version || ok != c.ok {
			t.Errorf("npmPackageRef(%q) = %q %q %v", c.purl, n, v, ok)
		}
	}
}
