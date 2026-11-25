package jsanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestLaunchDigest: the digest moves with every text the lane infers entry points from, in a
// package.json, a launch file or an interpreter-line file, and with nothing else.
func TestLaunchDigest(t *testing.T) {
	const root = `{"name": "app", "version": "1.0.0", "scripts": {"start": "node server.js", "build": "tsc"}, "bin": {"app": "cli.js"}}`
	base := map[string]string{"package.json": root, "server.js": "console.log(1)\n"}
	with := func(over map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name  string
		files map[string]string
		same  bool
	}{
		{"a script command changed", with(map[string]string{"package.json": `{"name": "app", "version": "1.0.0", "scripts": {"start": "node other.js", "build": "tsc"}, "bin": {"app": "cli.js"}}`}), false},
		{"a script added", with(map[string]string{"package.json": `{"name": "app", "version": "1.0.0", "scripts": {"start": "node server.js", "build": "tsc", "postinstall": "node setup.js"}, "bin": {"app": "cli.js"}}`}), false},
		{"a bin target changed", with(map[string]string{"package.json": `{"name": "app", "version": "1.0.0", "scripts": {"start": "node server.js", "build": "tsc"}, "bin": {"app": "bin/cli.js"}}`}), false},
		{"bin as a string", with(map[string]string{"package.json": `{"name": "app", "version": "1.0.0", "scripts": {"start": "node server.js", "build": "tsc"}, "bin": "cli.js"}`}), false},
		{"main added", with(map[string]string{"package.json": `{"name": "app", "version": "1.0.0", "main": "lib/index.js", "scripts": {"start": "node server.js", "build": "tsc"}, "bin": {"app": "cli.js"}}`}), false},
		{"a tool config preloads a module", with(map[string]string{"package.json": `{"name": "app", "version": "1.0.0", "mocha": {"require": "foo/register"}, "scripts": {"start": "node server.js", "build": "tsc"}, "bin": {"app": "cli.js"}}`}), false},
		{"a workspace member's script changed", with(map[string]string{"packages/web/package.json": `{"scripts": {"start": "vite"}}`}), false},
		{"a dot-directory package.json", with(map[string]string{".github/actions/x/package.json": `{"scripts": {"build": "node -r foo/register x.js"}}`}), false},
		{"a first-party package.json moved", map[string]string{"sub/package.json": root, "server.js": "console.log(1)\n"}, false},
		{"unparsable package.json", with(map[string]string{"package.json": `{"scripts": {`}), false},
		{"a Dockerfile", with(map[string]string{"Dockerfile": "FROM node:20\nCMD [\"node\", \"-r\", \"foo/register\", \"server.js\"]\n"}), false},
		{"a CI workflow", with(map[string]string{".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: node -r foo/register x.js\n"}), false},
		{"an interpreter-line file", with(map[string]string{"tools/run": "#!/usr/bin/env node\nrequire('foo')\n"}), false},
		{"a source file sets NODE_OPTIONS", with(map[string]string{"server.js": "process.env.NODE_OPTIONS = '-r foo/register'\n"}), false},
		{"a source file the lane does not parse", with(map[string]string{"src/view.mts": "export const x = 1\n"}), false},
		{"keys reordered", with(map[string]string{"package.json": "{\n  \"bin\": {\"app\": \"cli.js\"},\n  \"scripts\": {\"build\": \"tsc\", \"start\": \"node server.js\"},\n  \"version\": \"1.0.0\", \"name\": \"app\"\n}"}), true},
		{"a prose or dependency field changed", with(map[string]string{"package.json": `{"name": "app", "version": "2.0.0", "description": "x", "dependencies": {"left-pad": "^1.3.0"}, "scripts": {"start": "node server.js", "build": "tsc"}, "bin": {"app": "cli.js"}}`}), true},
		{"a node_modules package.json", with(map[string]string{"node_modules/left-pad/package.json": `{"scripts": {"install": "node evil.js"}}`}), true},
		{"a .git file", with(map[string]string{".git/config.yml": "x: node evil.js\n"}), true},
		{"a source file edited", with(map[string]string{"server.js": "console.log(2)\n"}), true},
		{"a prose file", with(map[string]string{"README.md": "run `node -r foo/register`\n"}), true},
	}
	want := LaunchDigest(writeProgram(t, base))
	if want == "" {
		t.Fatal("digest of a tree with a package.json is empty")
	}
	if again := LaunchDigest(writeProgram(t, base)); again != want {
		t.Fatalf("digest of the same tree differs: %q, %q", want, again)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LaunchDigest(writeProgram(t, tc.files))
			if (got == want) != tc.same {
				t.Errorf("digest equal to the base tree's = %v, want %v", got == want, tc.same)
			}
		})
	}
	for name, files := range map[string]map[string]string{
		"no package.json":             {"go.mod": "module m\n", "Dockerfile": "FROM x\n"},
		"only a node_modules package": {"node_modules/x/package.json": `{"scripts": {"a": "b"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			if got := LaunchDigest(writeProgram(t, files)); got != "" {
				t.Errorf("digest = %q, want empty", got)
			}
		})
	}
	t.Run("no dir", func(t *testing.T) {
		if got := LaunchDigest(""); got != "" {
			t.Errorf("digest = %q, want empty", got)
		}
	})
}

// TestResolveInventoryReportsLaunchDigest: the inventory carries the tree's launch digest, with a
// lockfile and without one, so the host can compare launch surfaces without linking the lane.
func TestResolveInventoryReportsLaunchDigest(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"locked": {
			"package.json":      `{"name": "app", "version": "1.0.0", "scripts": {"start": "node server.js"}}`,
			"package-lock.json": `{"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app", "version": "1.0.0"}, "node_modules/left-pad": {"version": "1.4.0"}}}`,
		},
		"no lockfile": {"package.json": `{"name": "app", "version": "1.0.0", "scripts": {"start": "node server.js"}}`},
		// No project root (root discovery skips dot-directories), but a launch text the lane reads.
		"no project root": {".github/actions/x/package.json": `{"scripts": {"build": "node -r foo/register x.js"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeProgram(t, files)
			inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
			if err != nil {
				t.Fatalf("ResolveInventory: %v", err)
			}
			if want := LaunchDigest(dir); want == "" || inv.LaunchDigest != want {
				t.Fatalf("LaunchDigest = %q, want %q", inv.LaunchDigest, want)
			}
		})
	}
}
