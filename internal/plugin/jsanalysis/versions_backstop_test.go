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
		{"Dockerfile-prod", "Dockerfile-prod", "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci && npm install express@4.18.2\n", true, "Dockerfile-prod:4"},
		{"bare yarn installs", "ci/steps.yml", "steps:\n  - command: yarn\n", true, "ci/steps.yml:2"},
		{"lowercase Dockerfile-like heredoc", "Dockerfile-prod", "from node:20\nRUN <<EOF\nnpm install express@4.18.2\nEOF\n", true, "Dockerfile-prod:2"},
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
