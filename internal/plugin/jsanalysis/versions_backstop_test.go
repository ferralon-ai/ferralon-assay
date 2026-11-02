package jsanalysis

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// An npm install in a file no surface rule reads withholds as the same line in install.sh
// does: express's lock pin is no longer claimed, left-pad's absence is no longer proven, and the
// reason names the file and line. Prose naming the same install changes nothing.
func TestResolveVersions_UnrecognisedInstallSurface(t *testing.T) {
	const lock = `{"name":"app","lockfileVersion":3,"packages":{` +
		`"":{"name":"app","version":"1.0.0","dependencies":{"express":"4.19.2"}},` +
		`"node_modules/express":{"version":"4.19.2"}}}`
	tests := []struct {
		name  string
		file  string
		body  string
		want  bool   // withheld
		cause string // the reason's file:line, or "" when a surface rule withholds instead
	}{
		{"control: install.sh", "install.sh", "npm install express@4.18.2\n", true, ""},
		{"Earthfile", "Earthfile", "VERSION 0.8\nbuild:\n    FROM node:20\n    RUN npm install express@4.18.2\n", true, ""},
		{"Buildkite", ".buildkite/pipeline.yml", "steps:\n  - command: npm install express@4.18.2\n", true, ""},
		{"Gitea", ".gitea/workflows/ci.yml", "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm install express@4.18.2\n", true, ""},
		{"scripts/*.js execSync", "scripts/setup.js", "const { execSync } = require('child_process')\nexecSync('npm install express@4.18.2', { stdio: 'inherit' })\n", true, "scripts/setup.js:2"},
		{"scripts/*.mjs spawn argv", "scripts/setup.mjs", "import { spawnSync } from 'node:child_process'\nspawnSync('npm', ['install', 'express@4.18.2'])\n", true, "scripts/setup.mjs:2"},
		{"Dockerfile-prod, a surface by name", "Dockerfile-prod", "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci && npm install express@4.18.2\n", true, ""},
		{"myDockerfile", "myDockerfile", "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci && npm install express@4.18.2\n", true, "myDockerfile:4"},
		{"bare yarn installs", "ci/steps.yml", "steps:\n  - command: yarn\n", true, "ci/steps.yml:2"},
		{"lowercase Dockerfile-like heredoc", "myDockerfile", "from node:20\nRUN <<EOF\nnpm install express@4.18.2\nEOF\n", true, "myDockerfile:2"},
		{"single-quoted YAML continuation", "ci/steps.yml", "steps:\n  - command: 'echo start &&\n      npm install express@4.18.2'\n", true, "ci/steps.yml:2"},
		{"steps under e2e", "e2e/ci.yml", "steps:\n  - command: npm install express@4.18.2\n", true, "e2e/ci.yml:2"},
		{"JSON fixture under test", "test/fixtures/cfg.json", "{\"scripts\":{\"postinstall\":\"npm install express@4.18.2\"}}", false, ""},
		{"npx in .mcp.json", ".mcp.json", "{\"mcpServers\": {\"a\": {\"command\": \"npx\", \"args\": [\"-y\", \"@modelcontextprotocol/server-filesystem\"]}}}\n", false, ""},
		{"npx in .vscode/mcp.json", ".vscode/mcp.json", "{\"servers\": {\"a\": {\"type\": \"stdio\", \"command\": \"npx\", \"args\": [\"-y\", \"@modelcontextprotocol/server-filesystem\"]}}}\n", false, ""},
		{"npx in a JSON file that is not an MCP config", "ci/install.json", "{\"mcpServers\": {\"a\": {\"command\": \"npx\", \"args\": [\"-y\", \"@modelcontextprotocol/server-filesystem\"]}}}\n", true, "ci/install.json:1"},
		{"root package.json is a surface, not test data", "package.json", "{\"name\":\"app\",\"version\":\"1.0.0\",\"scripts\":{\"postinstall\":\"npm install left-pad@1.0.0\"}}", true, ""},
		{"Deno JSONC tasks with comments under tests", "tests/deno.jsonc", "{\n  // tasks\n  \"tasks\": {\"setup\": \"npm install left-pad@1.0.0\"}\n}\n", true, ""},
		{"Nx project with trailing commas", "apps/x/project.json", "{\n  \"targets\": {\n    \"setup\": {\n      \"options\": {\"commands\": [\"echo\", \"npm install left-pad@1.0.0\",]},\n    },\n  },\n}\n", true, "apps/x/project.json:4"},
		{"Nx JSON5 project under tests", "tests/project.json5", "{\n  targets: {setup: {options: {command: 'npm install left-pad@1.0.0'}}},\n}\n", true, "tests/project.json5:2"},
		{"Deno tasks under tests", "tests/deno.json", "{\"tasks\": {\"setup\": \"npm install left-pad@1.0.0\"}}\n", true, "tests/deno.json:1"},
		{"package.json under tests is a surface, not test data", "tests/e2e/package.json", "{\"name\":\"e2e\",\"version\":\"1.0.0\",\"scripts\":{\"postinstall\":\"npm install left-pad@1.0.0\"}}", true, ""},
		{"workflow named for tests", ".github/workflows/tests.yml", "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm install left-pad@1.0.0\n", true, ""},
		{"README.md", "README.md", "## Install\n\n```\nnpm install express@4.18.2\nRUN npm install express\n```\n", false, ""},
		{"docs/*.rst", "docs/install.rst", "Install\n=======\n\n.. code-block:: console\n\n   $ npm install express@4.18.2\n", false, ""},
		{"CHANGELOG", "CHANGELOG", "1.0\n- run: npm install express now works\n", false, ""},
		{"a test under scripts", "scripts/setup.test.js", "execSync('npm install express@4.18.2')\n", false, ""},
		{"read-only npm", "ci/steps.yml", "steps:\n  - command: npm ls express\n  - command: npm --version\n", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeLockTree(t, map[string]string{"package.json": `{"name":"app","version":"1.0.0","dependencies":{"express":"4.19.2"}}`,
				"package-lock.json": lock, tt.file: tt.body})
			pin := resolveJS(t, dir, "express")
			absent := resolveJS(t, dir, "left-pad")
			if !tt.want && (!pin.Match.Resolved || !absent.Exhaustive) {
				t.Fatalf("express resolved %v, left-pad exhaustive %v; want both (reasons %v)", pin.Match.Resolved, absent.Exhaustive, absent.Partiality.Reasons)
			}
			if tt.want && (pin.Match.Resolved || absent.Exhaustive) {
				t.Fatalf("express resolved %v, left-pad exhaustive %v; want neither", pin.Match.Resolved, absent.Exhaustive)
			}
			if tt.cause == "" {
				return
			}
			want := []string{plugin.PartialReasonToolFailure, plugin.PartialReasonUnrecognisedInstallSurface + ":" + tt.cause}
			if !slices.Equal(absent.Partiality.Reasons, want) {
				t.Fatalf("reasons = %v, want %v", absent.Partiality.Reasons, want)
			}
		})
	}
}
