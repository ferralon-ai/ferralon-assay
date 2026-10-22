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
		{"poetry run pip install", map[string]string{"pyproject.toml": project, "poetry.lock": lockPoetry, "install.sh": "poetry run pip install jinja2==3.1.2\n"}, false, ""},
		{"bare pipenv install", map[string]string{"requirements.txt": reqs, "Pipfile": "[packages]\n", "Pipfile.lock": "{}\n", "install.sh": "pipenv install\n"}, false, ""},
		{"pipenv install --deploy with no Pipfile.lock", map[string]string{"requirements.txt": reqs, "Pipfile": "[packages]\n", "install.sh": "pipenv install --deploy\n"}, false, ""},
		{"pipenv run with a scripts table", map[string]string{"requirements.txt": reqs, "Pipfile": "[packages]\n\n[scripts]\nsetup = \"pip install jinja2==3.1.2\"\n", "Pipfile.lock": "{}\n", "install.sh": "pipenv run setup\n"}, false, ""},
		{"pdm run with a scripts table", map[string]string{"pyproject.toml": project + "[tool.pdm.scripts]\ntest = \"pip install jinja2==3.1.2\"\n", "pdm.lock": lockPDM, "install.sh": "pdm run test\n"}, false, ""},
		{"unknown installer: conda", map[string]string{"requirements.txt": reqs, "install.sh": "conda install jinja2\n"}, false, ""},
		{"unknown installer: mamba", map[string]string{"requirements.txt": reqs, "install.sh": "mamba install jinja2\n"}, false, ""},
		{"unknown installer: easy_install", map[string]string{"requirements.txt": reqs, "install.sh": "easy_install jinja2\n"}, false, ""},
		{"action input named for an installer", map[string]string{"requirements.txt": reqs, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: org/py-deps@v1\n        with:\n          uv-install: jinja2==3.1.2\n"}, false, ""},
		{"hatch run of a hatch script", map[string]string{"uv.lock": lockUV,
			"pyproject.toml": project + "[tool.hatch.envs.default.scripts]\nsetup = \"pip install jinja2==3.1.2\"\n", "install.sh": "hatch run setup\n"}, false, ""},
		{"poe task", map[string]string{"uv.lock": lockUV,
			"pyproject.toml": project + "[tool.poe.tasks]\nsetup = \"pip install jinja2==3.1.2\"\n", "install.sh": "poe setup\n"}, false, ""},
		{"poetry run poe: the run wrapper's argv names a runner", map[string]string{"pyproject.toml": project + "[tool.poe.tasks]\nsetup = \"pip install jinja2==3.1.2\"\n",
			"poetry.lock": lockPoetry, "install.sh": "poetry run poe setup\n"}, false, ""},
		{"invoke task", map[string]string{"requirements.txt": reqs, "tasks.py": "from invoke import task\n", "install.sh": "invoke setup\n"}, false, ""},
		{"inv task", map[string]string{"requirements.txt": reqs, "tasks.py": "from invoke import task\n", "Makefile": "setup:\n\tinv setup\n"}, false, ""},
		{"nox session installs", map[string]string{"requirements.txt": reqs, "noxfile.py": "import nox\n\n@nox.session\ndef t(s):\n    s.install(\"jinja2==3.1.2\")\n", "install.sh": "nox -s t\n"}, false, ""},
		{"tox env from a pyproject tox table", map[string]string{"pyproject.toml": project + "[tool.tox]\nlegacy_tox_ini = \"\"\"\n[testenv]\ndeps = jinja2==3.1.2\n\"\"\"\n", "uv.lock": lockUV, "install.sh": "tox -e py312\n"}, false, ""},
		{"tox env installs deps", map[string]string{"requirements.txt": reqs, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: tox -e py312\n"}, false, ""},
		{"rye sync", map[string]string{"pyproject.toml": project, "uv.lock": lockUV, "install.sh": "rye sync\n"}, false, ""},
		{"flit install", map[string]string{"pyproject.toml": project, "uv.lock": lockUV, "install.sh": "flit install --deps production\n"}, false, ""},
		{"pixi install", map[string]string{"requirements.txt": reqs, "install.sh": "pixi install\n"}, false, ""},
		{"setup.py install", map[string]string{"requirements.txt": reqs, "Dockerfile": docker + "pip install -r requirements.txt && python setup.py install\n"}, false, ""},
		{"pip3.12 named", map[string]string{"requirements.txt": reqs, "install.sh": "pip3.12 install jinja2==3.1.2\n"}, false, ""},
		{"python -m pip named", map[string]string{"requirements.txt": reqs, "install.sh": "python3 -m pip install jinja2==3.1.2\n"}, false, ""},
		{"python -mpip, module attached", map[string]string{"requirements.txt": reqs, "install.sh": "python3 -mpip install jinja2==3.1.2\n"}, false, ""},
		{"python -Impip, module attached to an option cluster", map[string]string{"requirements.txt": reqs, "install.sh": "python -Impip install -r requirements.txt\n"}, false, ""},
		{"python -mpip of a read file still withholds", map[string]string{"requirements.txt": reqs, "Makefile": "deps:\n\tpython -mpip install -r requirements.txt\n"}, false, ""},

		// Expansions, variables and lines that do not tokenise.
		{"PIP_INDEX_URL set by Dockerfile ENV", map[string]string{"requirements.txt": reqs,
			"Dockerfile": "FROM python:3.12\nENV PIP_INDEX_URL=https://pkgs.example.com/simple\nWORKDIR /app\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\n"}, false, ""},
		{"UV_ variable in CI", map[string]string{"pyproject.toml": project, "uv.lock": lockUV,
			".github/workflows/ci.yml": "on: push\nenv:\n  UV_INDEX_URL: https://pkgs.example.com/simple\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: uv sync --locked\n"}, false, ""},
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
		{"script fetches the file it installs", map[string]string{"requirements.txt": reqs,
			"install.sh": "curl -fsSL -o requirements.txt https://example.com/r.txt\npip install -r requirements.txt\n"}, false, ""},

		// Controls.
		{"pip install -r of a read file", map[string]string{"requirements.txt": reqs, "install.sh": "pip install --no-cache-dir -r requirements.txt\n"}, true, ""},
		{"Dockerfile pip install -r after COPY", map[string]string{"requirements.txt": reqs, "Dockerfile": docker + "pip install -q -r requirements.txt\nCOPY . .\nCMD [\"python\", \"app.py\"]\n"}, true, ""},
		{"uv sync --frozen with uv.lock", map[string]string{"pyproject.toml": project, "uv.lock": lockUV, "Dockerfile": uvDocker + "uv sync --frozen\n"}, true, ""},
		{"uv sync --locked with uv.lock", map[string]string{"pyproject.toml": project, "uv.lock": lockUV, "Makefile": "install:\n\tuv sync --locked\n"}, true, ""},
		{"poetry install with poetry.lock and [project]", map[string]string{"pyproject.toml": project, "poetry.lock": lockPoetry, "install.sh": "poetry install\n"}, true, ""},
		{"pdm sync with pdm.lock", map[string]string{"pyproject.toml": project, "pdm.lock": lockPDM, "install.sh": "pdm sync\n"}, true, ""},
		{"poetry run", map[string]string{"pyproject.toml": project, "poetry.lock": lockPoetry, "Procfile": "web: poetry run gunicorn app:app\n"}, true, ""},
		{"pipenv install --deploy", map[string]string{"requirements.txt": reqs, "Pipfile": "[packages]\n", "Pipfile.lock": "{}\n", "install.sh": "pipenv install --deploy\n"}, true, ""},
		{"pipenv sync", map[string]string{"requirements.txt": reqs, "Pipfile": "[packages]\n", "Pipfile.lock": "{}\n", "Makefile": "deps:\n\tpipenv sync\n"}, true, ""},
		{"noxfile that never installs, run by nox", map[string]string{"requirements.txt": reqs, "noxfile.py": "import nox\n\n@nox.session\ndef t(s):\n    s.run(\"pytest\")\n", "install.sh": "nox -s t\n"}, true, ""},
		{"pdm run without a scripts table", map[string]string{"pyproject.toml": project, "pdm.lock": lockPDM, "Makefile": "test:\n\tpdm run pytest\n"}, true, ""},
		{"pipenv run without a scripts table", map[string]string{"requirements.txt": reqs, "Pipfile": "[packages]\n", "Pipfile.lock": "{}\n", "Procfile": "web: pipenv run gunicorn app:app\n"}, true, ""},
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
