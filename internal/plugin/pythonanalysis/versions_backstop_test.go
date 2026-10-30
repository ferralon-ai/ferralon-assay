package pythonanalysis

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// An install in a file no surface rule reads withholds as the same line in install.sh does:
// the lock's pin for jinja2 is no longer claimed, PyJWT's absence is no longer proven, and the
// reason names the file and line. Prose naming the same install changes nothing.
func TestResolveVersions_UnrecognisedInstallSurface(t *testing.T) {
	tests := []struct {
		name  string
		file  string
		body  string
		want  bool   // withheld
		cause string // the reason's file:line, or "" when a surface rule withholds instead
	}{
		{"control: install.sh", "install.sh", "pip install PyJWT==1.0.0\n", true, ""},
		{"Earthfile", "Earthfile", "VERSION 0.8\nbuild:\n    FROM python:3.12\n    RUN pip install PyJWT==1.0.0\n", true, ""},
		{"Buildkite", ".buildkite/pipeline.yml", "steps:\n  - command: pip install PyJWT==1.0.0\n", true, ""},
		{"Gitea", ".gitea/workflows/ci.yml", "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pip install PyJWT==1.0.0\n", true, ""},
		{"invoke tasks.py", "tasks.py", "from invoke import task\n\n@task\ndef deps(c):\n    c.run(\"pip install PyJWT==1.0.0\")\n", true, "tasks.py:5"},
		{"tasks.py argv", "tasks.py", "import subprocess, sys\nsubprocess.check_call([sys.executable, \"-m\", \"pip\", \"install\", \"PyJWT==1.0.0\"])\n", true, "tasks.py:2"},
		{"Dockerfile-prod", "Dockerfile-prod", "FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN uv sync --frozen && pip install PyJWT==1.0.0\n", true, "Dockerfile-prod:4"},
		{"poe task", "pyproject.toml", exPyproject + "\n[tool.poe.tasks]\nsetup = \"pip install PyJWT==1.0.0\"\n", true, "pyproject.toml:6"},
		{"uv run in a pre-commit config", ".pre-commit-config.yaml", "repos:\n  - repo: local\n    hooks:\n      - id: lint\n        entry: uv run ruff\n        language: system\n", true, ".pre-commit-config.yaml:5"},
		{"README.md", "README.md", "## Install\n\n```\npip install PyJWT==1.0.0\nRUN pip install PyJWT\n```\n", false, ""},
		{"docs/*.rst", "docs/install.rst", "Install\n=======\n\n.. code-block:: console\n\n   $ pip install PyJWT==1.0.0\n", false, ""},
		{"CHANGELOG", "CHANGELOG", "1.0\n- run: pip install PyJWT now works\n", false, ""},
		{"comment in a build script", "tasks.py", "# c.run(\"pip install PyJWT\")\n\"\"\"Run pip install PyJWT first.\"\"\"\n", false, ""},
		{"pip self-upgrade passes as in install.sh", ".buildkite/pipeline.yml", "steps:\n  - command: pip install -U pip\n", false, ""},
		{"read-only pip", "ci/steps.yml", "steps:\n  - command: pip freeze\n  - command: pip --version\n", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"pyproject.toml": exPyproject, "uv.lock": exUVLock, tt.file: tt.body}
			if tt.file == "pyproject.toml" {
				files["pyproject.toml"] = tt.body
			}
			dir := writeTree(t, files)
			pin := resolveVersion(t, dir, "jinja2")
			absent := resolveVersion(t, dir, "PyJWT")
			withheld := !pin.Match.Resolved && !absent.Exhaustive
			if !tt.want && (!pin.Match.Resolved || !absent.Exhaustive) {
				t.Fatalf("jinja2 resolved %v, PyJWT exhaustive %v; want both (reasons %v)", pin.Match.Resolved, absent.Exhaustive, absent.Partiality.Reasons)
			}
			if tt.want && !withheld {
				t.Fatalf("jinja2 resolved %v, PyJWT exhaustive %v; want neither", pin.Match.Resolved, absent.Exhaustive)
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
