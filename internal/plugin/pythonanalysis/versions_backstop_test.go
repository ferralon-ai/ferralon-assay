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
		{"pip under bash -c", "ci/steps.yml", "steps:\n  - command: bash -c \"pip install PyJWT==1.0.0\"\n", true, "ci/steps.yml:2"},
		{"pip by a venv path", "ci/steps.yml", "steps:\n  - command: ./venv/bin/pip install PyJWT==1.0.0\n", true, "ci/steps.yml:2"},
		{"get-pip piped into python", "ci/steps.yml", "steps:\n  - command: curl -sS https://bootstrap.pypa.io/get-pip.py | python3 - PyJWT==1.0.0\n", true, "ci/steps.yml:2"},
		{"get-pip through a filter", "ci/steps.yml", "steps:\n  - command: curl -sS https://bootstrap.pypa.io/get-pip.py | sed 's/a/b/' | python3 - PyJWT==1.0.0\n", true, "ci/steps.yml:2"},
		{"get-pip through tee", "ci/steps.yml", "steps:\n  - command: curl -sS https://bootstrap.pypa.io/get-pip.py | tee g.py | python3 - PyJWT==1.0.0\n", true, "ci/steps.yml:2"},
		{"get-pip in a process substitution", "ci/steps.yml", "steps:\n  - command: python3 <(curl -sS https://bootstrap.pypa.io/get-pip.py) PyJWT==1.0.0\n", true, "ci/steps.yml:2"},
		{"get-pip into an output process substitution", "ci/steps.yml", "steps:\n  - command: curl -sS https://bootstrap.pypa.io/get-pip.py | tee >(python3 - PyJWT==1.0.0) >/dev/null\n", true, "ci/steps.yml:2"},
		{"Nx project under tests", "tests/project.json", "{\"name\": \"tests\", \"targets\": {\"setup\": {\"executor\": \"nx:run-commands\", \"options\": {\"commands\": [\"pip install PyJWT==1.0.0\"]}}}}\n", true, "tests/project.json:1"},
		{"Deno tasks under tests", "tests/deno.json", "{\"tasks\": {\"setup\": \"pip install PyJWT==1.0.0\"}}\n", true, "tests/deno.json:1"},
		{"single-quoted YAML continuation", "ci/steps.yml", "steps:\n  - command: 'echo start &&\n      pip install PyJWT==1.0.0'\n", true, "ci/steps.yml:2"},
		{"poe task in a pyproject under tests", "tests/pyproject.toml", "[tool.poe.tasks]\nsetup = \"pip install PyJWT==1.0.0\"\n", true, "tests/pyproject.toml:2"},
		{"Buildkite steps under ci/tests", "ci/tests/pipeline.yml", "steps:\n  - command: pip install PyJWT==1.0.0\n", true, "ci/tests/pipeline.yml:2"},
		{"uvx in .mcp.json", ".mcp.json", "{\"mcpServers\": {\"a\": {\"command\": \"uvx\", \"args\": [\"mcp-server-git\"]}}}\n", false, ""},
		{"uvx in an MCP fixture under tests", "tests/fixtures/mcp_configs/uvx.json", "{\"mcpServers\": {\"a\": {\"command\": \"uvx\", \"args\": [\"mcp-server-git\"]}}}\n", false, ""},
		{"uvx in a JSON file that is not an MCP config", "ci/install.json", "{\"mcpServers\": {\"a\": {\"command\": \"uvx\", \"args\": [\"mcp-server-git\"]}}}\n", true, "ci/install.json:1"},
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

// A package module named like a build script is exempt only while nothing outside Python
// source mentions it.
func TestResolveVersions_PackageModuleMentioned(t *testing.T) {
	const install = "import subprocess, sys\nsubprocess.check_call([sys.executable, \"-m\", \"pip\", \"install\", \"PyJWT==1.0.0\"])\n"
	wf := func(run string) string {
		return "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: " + run + "\n"
	}
	tests := []struct {
		name  string
		files map[string]string
		want  bool // withheld
	}{
		{"module alone", map[string]string{}, false},
		{"pre-commit hook runs it", map[string]string{".pre-commit-config.yaml": "repos:\n  - repo: local\n    hooks:\n      - id: deps\n        entry: python -m mypkg.build\n        language: system\n"}, true},
		{"workflow runs it after cd", map[string]string{".github/workflows/ci.yml": wf("cd src && python -m mypkg.build")}, true},
		{"setup.py imports it in a parenthesised group", map[string]string{"setup.py": "from setuptools import setup\nfrom mypkg import (\n    build,\n)\nsetup(name=\"app\")\n"}, true},
		{"workflow runs it after cd into its package", map[string]string{".github/workflows/ci.yml": wf("cd mypkg && python build.py")}, true},
		{"batch file runs it by backslashed path", map[string]string{"make.bat": "@echo off\r\npython mypkg\\build.py\r\n"}, true},
		{"CMake runs it", map[string]string{"CMakeLists.txt": "project(x)\nadd_custom_target(deps ALL COMMAND python -m mypkg.build)\n"}, true},
		{"workflow runs a longer-named sibling", map[string]string{"mypkg/build_utils.py": "", ".github/workflows/ci.yml": wf("python -m mypkg.build_utils")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"pyproject.toml": exPyproject, "uv.lock": exUVLock, "mypkg/__init__.py": "", "mypkg/build.py": install}
			for k, v := range tt.files {
				files[k] = v
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
			if !tt.want {
				return
			}
			want := []string{plugin.PartialReasonToolFailure, plugin.PartialReasonUnrecognisedInstallSurface + ":mypkg/build.py:2"}
			if !slices.Equal(absent.Partiality.Reasons, want) {
				t.Fatalf("reasons = %v, want %v", absent.Partiality.Reasons, want)
			}
		})
	}
}
