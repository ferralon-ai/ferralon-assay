package pythonanalysis

import (
	"path/filepath"
	"testing"
)

// A script surface that installs a Python package in any form other than the allowed ones, or
// whose allowed install does not bind to files read here, withholds every pin: the build may
// install a version no manifest read here records. Rows name the guard each depends on.
func TestResolveVersions_ScriptInstallVeto(t *testing.T) {
	const (
		reqs   = "jinja2==3.1.4\n"
		docker = "FROM python:3.12\nWORKDIR /app\nCOPY requirements.txt .\nRUN "
		lockUV = "version = 1\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n" +
			"[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
		lockPoetry = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
		lockPDM    = "[metadata]\ngroups = [\"default\"]\n\n[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
		project    = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1\"]\n"
		stale      = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1.5\"]\n"
		uvDocker   = "FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml uv.lock ./\nRUN "
	)
	tests := []struct {
		name  string
		files map[string]string
		want  bool
		root  string // the build root, under the tree written
	}{
		// The repros: a version installed only by a script command.
		{"repro: Dockerfile pins jinja2", map[string]string{"requirements.txt": reqs,
			"Dockerfile": docker + "pip install -r requirements.txt && pip install jinja2==3.1.2\n"}, false, ""},
		{"repro: install.sh pins jinja2", map[string]string{"requirements.txt": reqs,
			"install.sh": "#!/bin/sh\npip install -r requirements.txt\npip install jinja2==3.1.2\n"}, false, ""},
		{"repro: package.json postinstall pins jinja2", map[string]string{"requirements.txt": reqs,
			"web/package.json": `{"name":"web","scripts":{"postinstall":"pip install jinja2==3.1.2"}}`}, false, ""},

		// Named installs, runners and installers outside the allowed forms.
		{"transitive: pip install gunicorn", map[string]string{"requirements.txt": reqs, "install.sh": "pip install gunicorn\n"}, false, ""},
		{"pipx", map[string]string{"requirements.txt": reqs, "install.sh": "pipx install black\n"}, false, ""},
		{"uvx", map[string]string{"requirements.txt": reqs, "Makefile": "lint:\n\tuvx ruff check\n"}, false, ""},
		{"uv run syncs", map[string]string{"requirements.txt": reqs, "Makefile": "test:\n\tuv run pytest\n"}, false, ""},
		{"bare uv sync re-locks", map[string]string{"pyproject.toml": project, "uv.lock": lockUV, "Dockerfile": uvDocker + "uv sync\n"}, false, ""},
		{"pdm install re-locks", map[string]string{"pyproject.toml": project, "pdm.lock": lockPDM, "install.sh": "pdm install\n"}, false, ""},
		{"pdm install --frozen-lockfile", map[string]string{"pyproject.toml": project, "pdm.lock": lockPDM, "install.sh": "pdm install --frozen-lockfile\n"}, false, ""},
		{"chained allowed then named", map[string]string{"requirements.txt": reqs, "install.sh": "pip install -r requirements.txt && pip install flask\n"}, false, ""},
		{"named install behind sudo", map[string]string{"requirements.txt": reqs, "install.sh": "sudo pip install jinja2==3.1.2\n"}, false, ""},
		{"named install behind xargs", map[string]string{"requirements.txt": reqs, "install.sh": "xargs -a extra.txt pip install\n"}, false, ""},
		{"poetry run pip install", map[string]string{"pyproject.toml": project, "poetry.lock": lockPoetry, "install.sh": "poetry run pip install jinja2==3.1.2\n"}, false, ""},
		{"pdm run with a scripts table", map[string]string{"pyproject.toml": project + "[tool.pdm.scripts]\ntest = \"pip install jinja2==3.1.2\"\n", "pdm.lock": lockPDM, "install.sh": "pdm run test\n"}, false, ""},
		{"unknown installer: conda", map[string]string{"requirements.txt": reqs, "install.sh": "conda install jinja2\n"}, false, ""},
		{"unknown installer: mamba", map[string]string{"requirements.txt": reqs, "install.sh": "mamba install jinja2\n"}, false, ""},
		{"unknown installer: easy_install", map[string]string{"requirements.txt": reqs, "install.sh": "easy_install jinja2\n"}, false, ""},
		{"pip3.12 named", map[string]string{"requirements.txt": reqs, "install.sh": "pip3.12 install jinja2==3.1.2\n"}, false, ""},
		{"python -m pip named", map[string]string{"requirements.txt": reqs, "install.sh": "python3 -m pip install jinja2==3.1.2\n"}, false, ""},
		{"tox commands", map[string]string{"requirements.txt": reqs, "tox.ini": "[testenv]\ncommands_pre =\n    pip install jinja2==3.1.2\ncommands = pytest\n"}, false, ""},

		// Expansions, variables and lines that do not tokenise.
		{"$VAR argument", map[string]string{"requirements.txt": reqs, "install.sh": "pip install -r $REQS\n"}, false, ""},
		{"variable installer", map[string]string{"requirements.txt": reqs, "Makefile": "deps:\n\t$(VENV)/bin/pip install -r requirements.txt\n"}, false, ""},
		{"redirect", map[string]string{"requirements.txt": reqs, "install.sh": "pip install -r requirements.txt > /tmp/log\n"}, false, ""},
		{"PIP_INDEX_URL set by Dockerfile ENV", map[string]string{"requirements.txt": reqs,
			"Dockerfile": "FROM python:3.12\nENV PIP_INDEX_URL=https://pkgs.example.com/simple\nWORKDIR /app\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\n"}, false, ""},
		{"UV_ variable in CI", map[string]string{"pyproject.toml": project, "uv.lock": lockUV,
			".github/workflows/ci.yml": "on: push\nenv:\n  UV_INDEX_URL: https://pkgs.example.com/simple\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: uv sync --locked\n"}, false, ""},
		{"unterminated quote", map[string]string{"requirements.txt": reqs, "install.sh": "echo 'x && pip install jinja2\n"}, false, ""},
		{"unjoined continuation", map[string]string{"requirements.txt": reqs, "install.sh": "pip install -r requirements.txt \\"}, false, ""},
		{"flag outside the allowed set", map[string]string{"requirements.txt": reqs, "install.sh": "pip install --index-url https://x -r requirements.txt\n"}, false, ""},

		// What an allowed install reads.
		{"-r of a file not read", map[string]string{"requirements.txt": reqs, "tools.txt": "# tools\n", "install.sh": "pip install -r tools.txt\n"}, false, ""},
		{"unpinned requirement", map[string]string{"requirements.txt": "jinja2>=3\n", "install.sh": "pip install -r requirements.txt\n"}, false, ""},
		{"poetry install with no lock resolves afresh", map[string]string{"requirements.txt": reqs,
			"pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"flask>=3\"]\n", "install.sh": "poetry install\n"}, false, ""},
		{"stale uv.lock under uv sync --frozen", map[string]string{"pyproject.toml": stale, "uv.lock": lockUV, "Dockerfile": uvDocker + "uv sync --frozen\n"}, false, ""},
		{"stale poetry.lock under poetry install", map[string]string{"pyproject.toml": stale, "poetry.lock": lockPoetry, "install.sh": "poetry install\n"}, false, ""},
		{"stale pdm.lock under pdm sync", map[string]string{"pyproject.toml": stale, "pdm.lock": lockPDM, "install.sh": "pdm sync\n"}, false, ""},

		// Binding: the directory a command runs in and the file it reads there.
		{"cd outside the tree", map[string]string{"requirements.txt": reqs, "install.sh": "cd /opt/x && pip install -r requirements.txt\n"}, false, ""},
		{"CI working-directory outside the tree", map[string]string{"requirements.txt": reqs,
			".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        working-directory: ../other\n    steps:\n      - run: pip install -r requirements.txt\n"}, false, ""},
		{"upward walk leaves the tree", map[string]string{"requirements.txt": reqs, "sub/run.sh": "uv sync --frozen\n"}, false, ""},
		{"upward walk reaches a manifest outside the build root", map[string]string{"pyproject.toml": project, "uv.lock": lockUV, "app/requirements.txt": reqs, "app/sub/run.sh": "uv sync --frozen\n"}, false, "app"},
		{"Dockerfile without WORKDIR", map[string]string{"requirements.txt": reqs, "Dockerfile": "FROM python:3.12\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\n"}, false, ""},
		{"Dockerfile installs a file it fetched", map[string]string{"requirements.txt": reqs,
			"Dockerfile": "FROM python:3.12\nWORKDIR /app\nRUN curl -fsSL https://example.com/r.txt -o /tmp/r.txt\nRUN pip install -r /tmp/r.txt\n"}, false, ""},
		{"Dockerfile rewrites the file after COPY", map[string]string{"requirements.txt": reqs,
			"Dockerfile": docker + "python scripts/rewrite.py\nRUN pip install -r requirements.txt\n"}, false, ""},
		{"Dockerfile COPY --from naming a context path", map[string]string{"requirements.txt": reqs,
			"Dockerfile": "FROM python:3.12 AS builder\nRUN true\nFROM python:3.12\nWORKDIR /app\nCOPY requirements.txt .\nCOPY --from=builder requirements.txt .\nRUN pip install -r requirements.txt\n"}, false, ""},
		{"Dockerfile COPY glob with a wildcard directory", map[string]string{"requirements.txt": reqs, "svc/requirements.txt": reqs,
			"Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY requirements.txt .\nCOPY */requirements.txt ./\nRUN pip install -r requirements.txt\n"}, false, ""},
		{"Dockerfile COPY --from over the file", map[string]string{"requirements.txt": reqs,
			"Dockerfile": "FROM python:3.12 AS builder\nRUN true\nFROM python:3.12\nWORKDIR /app\nCOPY requirements.txt .\nCOPY --from=builder /x/requirements.txt .\nRUN pip install -r requirements.txt\n"}, false, ""},
		{"script fetches the file it installs", map[string]string{"requirements.txt": reqs,
			"install.sh": "curl -fsSL -o requirements.txt https://example.com/r.txt\npip install -r requirements.txt\n"}, false, ""},

		// Controls.
		{"pip install -r of a read file", map[string]string{"requirements.txt": reqs, "install.sh": "pip install --no-cache-dir -r requirements.txt\n"}, true, ""},
		{"Dockerfile pip install -r after COPY", map[string]string{"requirements.txt": reqs, "Dockerfile": docker + "pip install -q -r requirements.txt\nCOPY . .\nCMD [\"python\", \"app.py\"]\n"}, true, ""},
		{"cd to an in-tree directory", map[string]string{"app/requirements.txt": reqs, "install.sh": "cd app && pip install -r requirements.txt\n"}, true, ""},
		{"CI working-directory in the tree", map[string]string{"requirements.txt": reqs, "app/requirements.txt": reqs,
			".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        working-directory: app\n    steps:\n      - run: pip install -r requirements.txt\n"}, true, ""},
		{"uv sync --frozen with uv.lock", map[string]string{"pyproject.toml": project, "uv.lock": lockUV, "Dockerfile": uvDocker + "uv sync --frozen\n"}, true, ""},
		{"uv sync --locked with uv.lock", map[string]string{"pyproject.toml": project, "uv.lock": lockUV, "Makefile": "install:\n\tuv sync --locked\n"}, true, ""},
		{"poetry install with poetry.lock and [project]", map[string]string{"pyproject.toml": project, "poetry.lock": lockPoetry, "install.sh": "poetry install\n"}, true, ""},
		{"pdm sync with pdm.lock", map[string]string{"pyproject.toml": project, "pdm.lock": lockPDM, "install.sh": "pdm sync\n"}, true, ""},
		{"surface with no installer", map[string]string{"requirements.txt": reqs, "install.sh": "#!/bin/sh\nset -e\npython -m app\n"}, true, ""},
		{"poetry run", map[string]string{"pyproject.toml": project, "poetry.lock": lockPoetry, "Procfile": "web: poetry run gunicorn app:app\n"}, true, ""},
		{"pdm run without a scripts table", map[string]string{"pyproject.toml": project, "pdm.lock": lockPDM, "Makefile": "test:\n\tpdm run pytest\n"}, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveVersion(t, filepath.Join(writeTree(t, tt.files), tt.root), "jinja2")
			if !r.Found {
				t.Fatalf("jinja2 not found: %+v", r.All)
			}
			if r.Match.Resolved != tt.want {
				t.Fatalf("Resolved = %v, want %v (match %+v)", r.Match.Resolved, tt.want, r.Match)
			}
		})
	}
}
