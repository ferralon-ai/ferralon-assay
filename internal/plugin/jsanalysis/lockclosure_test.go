package jsanalysis

import (
	"reflect"
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
		"package-lock.json":                                 lock,
		"v1/package-lock.json":                              `{"lockfileVersion":1,"dependencies":{"qs":{"version":"6.0.0"}}}`,
		"broken/package-lock.json":                          `{"lockfileVersion":3,"packages":{"":{},"node_modules/ok":{},"node_modules/broken":{"dependencies":{"gone":"1"}}}}`,
		"peer/package-lock.json":                            `{"lockfileVersion":3,"packages":{"":{},"node_modules/ok":{},"node_modules/needs-peer":{"peerDependencies":{"gone":"*"}}}}`,
		"disk/package-lock.json":                            `{"lockfileVersion":3,"packages":{"":{},"node_modules/ok":{},"node_modules/@s/p":{},"node_modules/ok/node_modules/inner":{}}}`,
		"disk/node_modules/.bin/ok":                         "",
		"disk/node_modules/ok/package.json":                 `{"name":"ok"}`,
		"disk/node_modules/@s/p/package.json":               `{"name":"@s/p"}`,
		"disk/node_modules/ok/node_modules/inner/index.js":  "",
		"stale/package-lock.json":                           `{"lockfileVersion":3,"packages":{"":{},"node_modules/ok":{}}}`,
		"stale/node_modules/ok/package.json":                `{"name":"ok"}`,
		"stale/node_modules/ok/node_modules/extra/index.js": "",
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
		{"a node_modules on disk that matches the lock is bounded", "disk", "ok", []string{"ok", "@s/p", "inner"}},
		{"a node_modules on disk holding a package the lock does not list is unbounded", "stale", "ok", nil},
	}
	lc := newLockClosures(dir)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lc.closureOf(tc.from, tc.pkg); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("closureOf(%q, %q) = %#v, want %#v", tc.from, tc.pkg, got, tc.want)
			}
		})
	}
	if got := newLockClosures(t.TempDir()).closureOf("", "qs"); got != nil {
		t.Errorf("no lockfile must be unbounded; got %#v", got)
	}
}

// TestLockClosures_NodePath: NODE_PATH set on any surface that may launch the production
// process adds resolution roots no lockfile lists, so every closure is unbounded. A mention
// that sets nothing, or a file that cannot configure the process, leaves it bounded.
func TestLockClosures_NodePath(t *testing.T) {
	const lock = `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/qs":{}}}`
	cases := []struct {
		name    string
		file    string
		body    string
		bounded bool
	}{
		{"Dockerfile ENV with =", "Dockerfile", "FROM node:20\nENV NODE_PATH=/srv/lib\n", false},
		{"Dockerfile ENV with a space", "deploy/Dockerfile.prod", "FROM node:20\nENV NODE_PATH /srv/lib\n", false},
		{"package.json script", "package.json", `{"name":"app","scripts":{"start":"NODE_PATH=src node index.js"}}`, false},
		{"workflow env", ".github/workflows/deploy.yml", "jobs:\n  run:\n    env:\n      NODE_PATH: src\n", false},
		{"Procfile", "Procfile", "web: NODE_PATH=lib node server.js\n", false},
		{"Kubernetes env list", "k8s/deployment.yaml", "env:\n  - name: NODE_PATH\n    value: /app/lib\n", false},
		{"env file", ".env.production", "NODE_PATH=lib\n", false},
		{"README mention", "README.md", "Set NODE_PATH=src to run locally.\n", true},
		{"a manifest that does not set it", "app.yaml", "runtime: nodejs20\nenv_variables:\n  NODE_ENV: production\n", true},
		{"a source file under node_modules", "node_modules/qs/package.json", `{"name":"qs","scripts":{"x":"NODE_PATH=a node"}}`, true},
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
