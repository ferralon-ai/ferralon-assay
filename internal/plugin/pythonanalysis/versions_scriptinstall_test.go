package pythonanalysis

import (
	"path/filepath"
	"slices"
	"strings"
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
		{"pdm run, scripts under a [tool.pdm] table", map[string]string{"pyproject.toml": project + "[tool.pdm]\nscripts.setup = \"pip install jinja2==3.1.2\"\n", "pdm.lock": lockPDM, "install.sh": "pdm run setup\n"}, false, ""},
		{"pdm run, scripts as an inline table", map[string]string{"pyproject.toml": project + "[tool.pdm]\nscripts = { setup = \"pip install jinja2==3.1.2\" }\n", "pdm.lock": lockPDM, "install.sh": "pdm run setup\n"}, false, ""},
		{"pdm run, spaced table header", map[string]string{"pyproject.toml": project + "[ tool.pdm.scripts ]\nsetup = \"pip install jinja2==3.1.2\"\n", "pdm.lock": lockPDM, "install.sh": "pdm run setup\n"}, false, ""},
		{"pdm run, pre_run hook around a plain command", map[string]string{"pyproject.toml": project + "[tool.pdm.scripts]\npre_run = \"pip install jinja2==3.1.2\"\n", "pdm.lock": lockPDM, "install.sh": "pdm run pytest\n"}, false, ""},
		{"pdm run, pyproject that does not decode", map[string]string{"pyproject.toml": project, "pdm.lock": lockPDM, "tools/pyproject.toml": "[tool.pdm\n", "tools/run.sh": "pdm run pytest\n"}, false, ""},
		{"pipenv run, spaced table header", map[string]string{"requirements.txt": reqs, "Pipfile": "[packages]\n\n[ scripts ]\nsetup = \"pip install jinja2==3.1.2\"\n", "Pipfile.lock": "{}\n", "install.sh": "pipenv run setup\n"}, false, ""},
		{"pipenv run, Pipfile that does not decode", map[string]string{"requirements.txt": reqs, "tools/Pipfile": "[packages\n", "tools/run.sh": "pipenv run gunicorn app:app\n"}, false, ""},
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
		{"UV_NO_DEV in CI: this lane keeps no variable", map[string]string{"pyproject.toml": project, "uv.lock": lockUV,
			".github/workflows/ci.yml": "on: push\nenv:\n  UV_NO_DEV: \"1\"\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: uv sync --locked\n"}, false, ""},
		{"PIP_ONLY_BINARY exported: this lane keeps no variable", map[string]string{"requirements.txt": reqs, "install.sh": "export PIP_ONLY_BINARY=:all:\npip install -r requirements.txt\n"}, false, ""},
		{"flag outside the allowed set", map[string]string{"requirements.txt": reqs, "install.sh": "pip install --index-url https://x -r requirements.txt\n"}, false, ""},

		{"folded run joins a pin to an allowed form", map[string]string{"requirements.txt": reqs, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: >\n          pip install -r requirements.txt\n          jinja2==3.1.2\n"}, false, ""},
		{"PowerShell pins jinja2", map[string]string{"requirements.txt": reqs, "install.ps1": "python -m pip install jinja2==3.1.2\n"}, false, ""},
		{"cmd pins jinja2", map[string]string{"requirements.txt": reqs, "install.cmd": "pip install jinja2==3.1.2\r\n"}, false, ""},
		{"GitLab string include pins jinja2", map[string]string{"requirements.txt": reqs, ".gitlab-ci.yaml": "include: ci/build.yml\n", "ci/build.yml": "build:\n  script:\n    - pip install jinja2==3.1.2\n"}, false, ""},
		{"plain run continued with a pin", map[string]string{"requirements.txt": reqs, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pip install -r requirements.txt\n          jinja2==3.1.2\n"}, false, ""},

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

		{"activate of a venv no command created", map[string]string{"requirements.txt": reqs, "install.sh": ". .venv/bin/activate\npip install -r requirements.txt\n"}, false, ""},
		{"activate of a venv other than the one created", map[string]string{"requirements.txt": reqs, "install.sh": "python -m venv a\n. b/bin/activate\npip install -r requirements.txt\n"}, false, ""},
		{"activate of a committed script that installs", map[string]string{"requirements.txt": reqs, "install.sh": "python -m venv venv\n. venv/bin/activate\npip install -r requirements.txt\n", "venv/bin/activate": "#!/bin/sh\npip install jinja2==3.1.2\n"}, false, ""},
		{"activate in a step after the one that created the venv", map[string]string{"requirements.txt": reqs, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: python -m venv .venv\n      - run: . .venv/bin/activate && pip install -r requirements.txt\n"}, false, ""},

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
		{"pdm run, a tool.pdm table without scripts", map[string]string{"pyproject.toml": project + "[tool.pdm]\ndistribution = false\n", "pdm.lock": lockPDM, "Makefile": "test:\n\tpdm run pytest\n"}, true, ""},
		{"python -m venv, activate, pip install -r", map[string]string{"requirements.txt": reqs, "install.sh": "python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt\n"}, true, ""},
		{"virtualenv, source activate, pip install -r", map[string]string{"requirements.txt": reqs, "install.sh": "virtualenv venv\nsource venv/bin/activate\npip install -r requirements.txt\n"}, true, ""},
		{"absolute venv activated in a CI run", map[string]string{"requirements.txt": reqs, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: python3 -m venv /opt/venv && . /opt/venv/bin/activate && pip install -r requirements.txt\n"}, true, ""},
		{"venv created and activated in a run block", map[string]string{"requirements.txt": reqs, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          python -m venv .venv\n          . .venv/bin/activate\n          pip install -r requirements.txt\n"}, true, ""},
		{"venv created in before_script and activated in script", map[string]string{"requirements.txt": reqs, ".gitlab-ci.yml": "build:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - pip install -r requirements.txt\n"}, true, ""},
		{"pipenv run, an empty scripts table", map[string]string{"requirements.txt": reqs, "Pipfile": "[packages]\n\n[scripts]\n", "Pipfile.lock": "{}\n", "Procfile": "web: pipenv run gunicorn app:app\n"}, true, ""},
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

// A pip self-upgrade installs pip and nothing else, so it withholds the pip coordinate alone;
// every other form around it keeps withholding every pin. Rows name the gate each depends on.
func TestResolveVersions_PipSelfUpgrade(t *testing.T) {
	const (
		reqs   = "jinja2==3.1.4\npip==24.0\n"
		docker = "FROM python:3.12\nWORKDIR /app\nCOPY requirements.txt .\nRUN "
	)
	tests := []struct {
		name string
		line string // run by install.sh
		pip  bool   // whether the line is a self-upgrade: jinja2 resolves and pip does not
	}{
		{"pip install -U pip", "pip install -U pip", true},
		{"pip install --upgrade pip", "pip install --upgrade pip", true},
		{"python -m pip install --upgrade pip", "python -m pip install --upgrade pip", true},
		{"pip3 --user", "pip3 install --user --upgrade pip", true},
		{"every reviewed flag", "python3.12 -m pip install -q --quiet --no-cache-dir --disable-pip-version-check --no-warn-script-location --root-user-action=ignore -U pip", true},
		{"pinned, quoted", `pip install "pip==24.0"`, true},
		{"compatible release and exclusion", `pip install --upgrade 'pip~=24.0,!=24.0.1'`, true},
		{"name case", "pip install -U Pip", true},
		{"chained before an allowed install", "pip install -U pip && pip install -r requirements.txt", true},

		// Another target.
		{"setuptools and wheel beside pip", "pip install -U pip setuptools wheel", false},
		{"setuptools alone", "pip install -U setuptools", false},
		{"wheel alone", "pip install -U wheel", false},
		{"another package beside pip", "pip install -U pip jinja2==3.1.2", false},
		{"pip beside a requirements file", "pip install -U pip -r requirements.txt", false},
		{"no target", "pip install -U", false},
		{"pip twice", "pip install -U pip pip==24.0", false},
		{"pipx is not pip", "pip install -U pipx", false},
		{"extras", "pip install -U 'pip[testing]'", false},
		{"marker", `pip install -U "pip; python_version > '3'"`, false},
		{"direct reference", `pip install -U "pip @ https://example.com/pip-24.0.tar.gz"`, false},
		{"URL", "pip install -U https://example.com/pip-24.0.tar.gz", false},
		{"path", "pip install -U ./pip", false},
		{"archive", "pip install -U pip-24.0-py3-none-any.whl", false},
		{"specifier with no version", `pip install "pip=="`, false},
		{"a range holding < or >, read as a redirect", `pip install --upgrade 'pip>=23,<25'`, false},
		{"variable target", "pip install -U $PKG", false},

		// Flags outside the reviewed list.
		{"-c", "pip install -U pip -c constraints.txt", false},
		{"-e", "pip install -U pip -e .", false},
		{"-i", "pip install -i https://pkgs.example.com/simple -U pip", false},
		{"--index-url=", "pip install --index-url=https://pkgs.example.com/simple -U pip", false},
		{"--extra-index-url", "pip install --extra-index-url https://pkgs.example.com/simple -U pip", false},
		{"--find-links", "pip install --find-links ./wheels -U pip", false},
		{"-f", "pip install -f ./wheels -U pip", false},
		{"--no-index", "pip install --no-index -U pip", false},
		{"--pre", "pip install --pre -U pip", false},
		{"clustered short flags", "pip install -qU pip", false},
		{"not install", "pip download pip", false},
		{"PIP_ variable set", "export PIP_INDEX_URL=https://pkgs.example.com/simple\npip install -U pip", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"requirements.txt": reqs, "install.sh": "#!/bin/sh\n" + tt.line + "\n"})
			r := resolveVersion(t, dir, "jinja2")
			if !r.Found || r.Match.Resolved != tt.pip {
				t.Fatalf("jinja2 Resolved = %v, want %v (match %+v)", r.Match.Resolved, tt.pip, r.Match)
			}
			if r.Partiality.Complete != tt.pip {
				t.Fatalf("jinja2 Partiality = %+v, want complete %v", r.Partiality, tt.pip)
			}
			p := resolveVersion(t, dir, "PIP")
			if !p.Found || p.Match.Resolved || p.Partiality.Complete || p.MatchesComplete {
				t.Fatalf("pip = %+v, want found, unresolved and partial", p)
			}
		})
	}

	// Controls: with no self-upgrade the pip pin resolves, and a Dockerfile one leaves the
	// requirements file it installs bound.
	t.Run("no self-upgrade: pip resolves", func(t *testing.T) {
		r := resolveVersion(t, writeTree(t, map[string]string{"requirements.txt": reqs, "install.sh": "pip install -r requirements.txt\n"}), "pip")
		if !r.Match.Resolved || r.Match.Version != "24.0" {
			t.Fatalf("pip = %+v, want 24.0 resolved", r.Match)
		}
	})
	t.Run("Dockerfile self-upgrade between COPY and install", func(t *testing.T) {
		dir := writeTree(t, map[string]string{"requirements.txt": reqs, "Dockerfile": docker + "pip install --upgrade pip\nRUN pip install -r requirements.txt\n"})
		if r := resolveVersion(t, dir, "jinja2"); !r.Match.Resolved {
			t.Fatalf("jinja2 = %+v, want resolved", r.Match)
		}
		if r := resolveVersion(t, dir, "pip"); r.Match.Resolved {
			t.Fatalf("pip = %+v, want unresolved", r.Match)
		}
	})
}

// Under a lock that covers the build, a self-upgrade leaves absence proven for every
// coordinate but pip, and declares pip to the import resolver.
func TestResolveVersions_PipSelfUpgradeExhaustive(t *testing.T) {
	dir := writeTree(t, map[string]string{"pyproject.toml": exPyproject, "uv.lock": exUVLock,
		"Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml uv.lock ./\nRUN pip install -U pip && uv sync --frozen\n"})
	if r := resolveVersion(t, dir, "PyJWT"); r.Found || !r.Exhaustive {
		t.Fatalf("PyJWT = found %v exhaustive %v, want absent and exhaustive", r.Found, r.Exhaustive)
	}
	if r := resolveVersion(t, dir, "pip"); r.Found || r.Exhaustive {
		t.Fatalf("pip = found %v exhaustive %v, want absent and not exhaustive", r.Found, r.Exhaustive)
	}
	names, complete, read := declaredDistributions(dir)
	if !names["pip"] || !complete || !read {
		t.Fatalf("declaredDistributions = %v complete %v read %v, want pip declared, complete and read", names, complete, read)
	}
}

// pip reads its index, find-links and every other install option from a config file a build
// can COPY into place, and from PIP_* variables, so either one in the tree withholds every pin
// around a self-upgrade, as on any other pip install of a package.
func TestResolveVersions_PipSelfUpgradeConfig(t *testing.T) {
	const (
		dockerHead = "FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml uv.lock ./\n"
		upgrade    = "RUN pip install -U pip && uv sync --frozen\n"
	)
	type row struct {
		name  string
		files map[string]string
		want  bool // PyJWT exhaustive
	}
	tests := []row{
		{"no config", map[string]string{"Dockerfile": dockerHead + upgrade}, true},

		{"pip.conf COPY'd to /etc", map[string]string{"pip.conf": "[global]\nextra-index-url = https://pkgs.example.com/simple\n",
			"Dockerfile": dockerHead + "COPY pip.conf /etc/pip.conf\n" + upgrade}, false},
		{"committed .venv/pip.conf", map[string]string{".venv/pip.conf": "[global]\nfind-links = /wheels\n", "Dockerfile": dockerHead + upgrade}, false},
		{"pip.ini", map[string]string{"config/pip.ini": "[global]\nindex-url = https://pkgs.example.com/simple\n", "Dockerfile": dockerHead + upgrade}, false},
		{"name case", map[string]string{"PIP.CONF": "[global]\nno-index = true\n", "Dockerfile": dockerHead + upgrade}, false},
		{"pre", map[string]string{"pip.conf": "[install]\npre = true\n", "Dockerfile": dockerHead + upgrade}, false},
		{"another option", map[string]string{"pip.conf": "[global]\ntimeout = 60\n", "Dockerfile": dockerHead + upgrade}, false},
		{"empty", map[string]string{"pip.conf": "", "Dockerfile": dockerHead + upgrade}, false},

		// pip reads a config where the build puts it, whatever the tree calls it, so a script
		// surface naming a pip config path withholds.
		{"COPY to /etc/pip.conf from another name", map[string]string{"config/pip-prod.cfg": "[global]\nindex-url = https://pkgs.example.com/simple\n",
			"Dockerfile": dockerHead + "COPY config/pip-prod.cfg /etc/pip.conf\n" + upgrade}, false},
		{"COPY to ~/.config/pip", map[string]string{"cfg/pip.cfg": "[global]\n", "Dockerfile": dockerHead + "COPY cfg/pip.cfg /root/.config/pip/pip.conf\n" + upgrade}, false},
		{"ADD from a URL", map[string]string{"Dockerfile": dockerHead + "ADD https://example.com/pip.conf /etc/pip.conf\n" + upgrade}, false},
		{"BuildKit secret mount", map[string]string{"Dockerfile": dockerHead + "RUN --mount=type=secret,id=pipconf,target=/etc/pip.conf pip install -U pip && uv sync --frozen\n"}, false},
		{"mention: pip.ini", map[string]string{"Dockerfile": dockerHead + "COPY cfg/win.cfg C:/ProgramData/pip/pip.ini\n" + upgrade}, false},
		{"mention: name case", map[string]string{"Dockerfile": dockerHead + "COPY cfg/x /ETC/PIP.CONF\n" + upgrade}, false},
		{"mention: PIP_CONFIG_FILE referenced", map[string]string{"Dockerfile": dockerHead + "RUN echo \"$PIP_CONFIG_FILE\"\n" + upgrade}, false},
		{"mention: pip.conf in a virtualenv", map[string]string{"Dockerfile": dockerHead + "COPY cfg/x /opt/venv/pip.conf\n" + upgrade}, false},
		{"mention: pip_config_file, lower case", map[string]string{"Dockerfile": dockerHead + "# see pip_config_file\n" + upgrade}, false},
		{"mention: pip config", map[string]string{"Dockerfile": dockerHead + "# settings: pip config list\n" + upgrade}, false},
		{"mention: /etc/xdg/pip", map[string]string{"Dockerfile": dockerHead + "COPY cfg/ /etc/xdg/pip/\n" + upgrade}, false},
		{"mention: .config/pip", map[string]string{"Dockerfile": dockerHead + "COPY cfg/ /root/.config/pip/\n" + upgrade}, false},
		{"mention: /etc/pip", map[string]string{"Dockerfile": dockerHead + "COPY cfg/ /etc/pip/\n" + upgrade}, false},
		{"mention in another surface", map[string]string{"Dockerfile": dockerHead + "COPY cfg/x /etc/pip.conf\n", "install.sh": "#!/bin/sh\npip install -U pip\n"}, false},
		{"mention in a GitLab local include", map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/setup.inc\nbuild:\n  script:\n    - pip install -U pip\n",
			"ci/setup.inc": "# pip reads /etc/pip.conf\nsetup:\n  script:\n    - echo ready\n"}, false},
		{"GitLab local include naming no config", map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/setup.inc\nbuild:\n  script:\n    - pip install -U pip\n",
			"ci/setup.inc": "setup:\n  script:\n    - echo ready\n"}, true},
	}
	for _, v := range []string{"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_NO_INDEX", "PIP_PRE", "PIP_CONFIG_FILE"} {
		tests = append(tests,
			row{v + " in Dockerfile ENV", map[string]string{"Dockerfile": dockerHead + "ENV " + v + "=x\n" + upgrade}, false},
			row{v + " in Dockerfile ARG", map[string]string{"Dockerfile": dockerHead + "ARG " + v + "=x\n" + upgrade}, false},
			row{v + " in the script", map[string]string{"install.sh": "#!/bin/sh\nexport " + v + "=x\npip install -U pip\nuv sync --frozen\n"}, false},
			row{v + " in another file", map[string]string{"Dockerfile": dockerHead + "ENV " + v + "=x\n", "install.sh": "#!/bin/sh\npip install -U pip\n"}, false},
		)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"pyproject.toml": exPyproject, "uv.lock": exUVLock}
			for k, v := range tt.files {
				files[k] = v
			}
			if r := resolveVersion(t, writeTree(t, files), "PyJWT"); r.Found || r.Exhaustive != tt.want {
				t.Fatalf("PyJWT = found %v exhaustive %v, want absent and exhaustive %v", r.Found, r.Exhaustive, tt.want)
			}
		})
	}

	// A requirements install beside a pip config resolves as before: only the self-upgrade
	// allowance reads the config.
	t.Run("pip.conf beside pip install -r", func(t *testing.T) {
		dir := writeTree(t, map[string]string{"requirements.txt": "jinja2==3.1.4\n", "pip.conf": "[global]\ntimeout = 60\n", "install.sh": "pip install -r requirements.txt\n"})
		if r := resolveVersion(t, dir, "jinja2"); !r.Match.Resolved {
			t.Fatalf("jinja2 = %+v, want resolved", r.Match)
		}
	})
}

// pdm sync runs the pre_install and post_install scripts of tool.pdm.scripts around the
// install, so either withholds every pin; the task runners that read pyproject.toml task
// tables (poe, hatch) withhold wherever they run.
func TestResolveVersions_PyprojectTaskInstalls(t *testing.T) {
	const (
		project = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1\"]\n"
		lockPDM = "[metadata]\ngroups = [\"default\"]\n\n[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
	)
	tests := []struct {
		name, pyproject, script string
		want                    bool // jinja2 resolved
	}{
		{"pdm sync, post_install", project + "[tool.pdm.scripts]\npost_install = \"pip install jinja2==3.1.2\"\n", "pdm sync\n", false},
		{"pdm sync, pre_install", project + "[tool.pdm.scripts]\npre_install = \"pip install jinja2==3.1.2\"\n", "pdm sync\n", false},
		{"pdm sync, hook as a dotted key", project + "[tool.pdm]\nscripts.post_install = \"pip install jinja2==3.1.2\"\n", "pdm sync\n", false},
		{"pdm sync, hook as a table", project + "[tool.pdm.scripts.post_install]\ncmd = \"pip install jinja2==3.1.2\"\n", "pdm sync\n", false},
		{"pdm sync, hook in a composite", project + "[tool.pdm.scripts]\npost_install = { composite = [\"pip install jinja2==3.1.2\"] }\n", "pdm sync\n", false},
		{"pdm sync, pre_invoke", project + "[tool.pdm.scripts]\npre_invoke = \"pip install jinja2==3.1.2\"\n", "pdm sync\n", false},
		{"pdm sync, scripts not a table", project + "[tool.pdm]\nscripts = [\"pip install jinja2==3.1.2\"]\n", "pdm sync\n", false},
		{"pdm sync, PDM_PROJECT exported", project, "export PDM_PROJECT=/app/sub\npdm sync\n", false},
		{"poe task", project + "[tool.poe.tasks]\nsetup = \"pip install jinja2==3.1.2\"\n", "pdm sync\npoe setup\n", false},
		{"poe task through python -m", project + "[tool.poe.tasks]\nsetup = \"pip install jinja2==3.1.2\"\n", "pdm sync\npython -m poethepoet setup\n", false},
		{"hatch env script", project + "[tool.hatch.envs.default.scripts]\nsetup = \"pip install jinja2==3.1.2\"\n", "pdm sync\nhatch run setup\n", false},

		// Guards: another script name, and no scripts table.
		{"pdm sync, another script", project + "[tool.pdm.scripts]\ntest = \"pytest\"\n", "pdm sync\n", true},
		{"pdm sync, no scripts", project, "pdm sync\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"pyproject.toml": tt.pyproject, "pdm.lock": lockPDM, "install.sh": "#!/bin/sh\n" + tt.script})
			r := resolveVersion(t, dir, "jinja2")
			if !r.Found || r.Match.Resolved != tt.want || r.Partiality.Complete != tt.want {
				t.Fatalf("jinja2 = %+v partiality %+v, want resolved and complete %v", r.Match, r.Partiality, tt.want)
			}
		})
	}
}

func TestResolveVersions_PDMSyncUnbound(t *testing.T) {
	tests := map[string]map[string]string{
		"no pyproject.toml": {"requirements.txt": "jinja2==3.1.4\n", "install.sh": "#!/bin/sh\npdm sync\n"},
		"pyproject.toml that doesn't decode": {
			"requirements.txt": "jinja2==3.1.4\n", "pyproject.toml": "[tool.pdm.scripts\npost_install = \"pip install jinja2==3.1.2\"\n",
			"pdm.lock": "[metadata]\ngroups = [\"default\"]\n", "install.sh": "#!/bin/sh\npdm sync\n",
		},
		"PDM_PROJECT in a Dockerfile": {
			"requirements.txt": "jinja2==3.1.4\n", "pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\n",
			"pdm.lock":   "[metadata]\ngroups = [\"default\"]\n",
			"Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY . .\nENV PDM_PROJECT=/app/sub\nRUN pdm sync\n",
		},
	}
	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, files), "jinja2")
			if !r.Found || r.Match.Resolved || r.Partiality.Complete {
				t.Fatalf("jinja2 = %+v partiality %+v, want unresolved and incomplete", r.Match, r.Partiality)
			}
		})
	}
}

func TestResolveVersions_PDMEnvKept(t *testing.T) {
	base := map[string]string{
		"requirements.txt": "jinja2==3.1.4\n", "pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\n",
		"pdm.lock": "[metadata]\ngroups = [\"default\"]\n",
	}
	tests := []struct {
		name, file, src string
		want            bool // jinja2 resolved
	}{
		{"PDM_CHECK_UPDATE", "Dockerfile", "FROM python:3.12\nWORKDIR /app\nCOPY . .\nENV PDM_CHECK_UPDATE=false\nRUN pdm sync\n", true},
		{"PDM_BUILD_SCM_VERSION", ".github/workflows/ci.yml", "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    env:\n      PDM_BUILD_SCM_VERSION: 1.0.0\n    steps:\n      - run: pdm sync\n", true},
		{"PDM_CHECK_UPDATE beside another PDM_ name", "Dockerfile", "FROM python:3.12\nWORKDIR /app\nCOPY . .\nENV PDM_CHECK_UPDATE=false PDM_LOCKFILE=other.lock\nRUN pdm sync\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{tt.file: tt.src}
			for k, v := range base {
				files[k] = v
			}
			r := resolveVersion(t, writeTree(t, files), "jinja2")
			if !r.Found || r.Match.Resolved != tt.want || r.Partiality.Complete != tt.want {
				t.Fatalf("jinja2 = %+v partiality %+v, want resolved and complete %v", r.Match, r.Partiality, tt.want)
			}
		})
	}
}

// poetry install with a terminal flag, --no-root or a group selection installs a subset of
// poetry.lock, so it keeps the pins and the lock's exhaustive claim; any other flag withholds.
// --no-root skips the root's tool.poetry.build script, but not its plugins or its path
// sources' builds, or the indexes those builds resolve from.
func TestResolveVersions_PoetryInstallFlags(t *testing.T) {
	const (
		project    = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1\"]\n"
		lockPoetry = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\ngroups = [\"main\"]\n"
		setupPy    = "import subprocess\nsubprocess.run([\"pip\", \"install\", \"jinja2==3.1.2\"])\n"
		pathLock   = "[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\ndevelop = true\n\n[package.source]\ntype = \"directory\"\nurl = \"lib\"\n\n" + lockPoetry
		lib        = "[project]\nname = \"lib\"\nversion = \"0.1.0\"\n[build-system]\nrequires = [\"x\"]\nbuild-backend = \"setuptools.build_meta\"\n"
	)
	tests := []struct {
		name, args string
		files      map[string]string // more files in the tree, over pyproject.toml and poetry.lock
		want       bool              // jinja2 resolved, and an unlocked coordinate exhaustive
	}{
		{"--no-root --no-interaction", "--no-root --no-interaction", nil, true},
		{"-n --no-ansi", "-n --no-ansi", nil, true},
		{"--ansi -q", "--ansi -q", nil, true},
		{"--only main", "--only main", nil, true},
		{"--only=main", "--only=main", nil, true},
		{"--without dev", "--without dev", nil, true},
		{"--with docs", "--with docs", nil, true},
		{"--with a,b repeated", "--with docs,lint --with test --without dev", nil, true},
		{"--no-dev --no-root", "--no-dev --no-root", nil, true},
		{"--no-root skips the build script", "--no-root", map[string]string{"pyproject.toml": project + "[tool.poetry]\nbuild = \"build.py\"\n", "build.py": setupPy}, true},

		{"build script without --no-root", "--only main", map[string]string{"pyproject.toml": project + "[tool.poetry]\nbuild = \"build.py\"\n", "build.py": setupPy}, false},
		{"--no-root still loads requires-plugins", "--no-root", map[string]string{"pyproject.toml": project + "[tool.poetry.requires-plugins]\npoetry-plugin-export = \">=1.8\"\n"}, false},
		{"--no-root still loads .poetry/plugins", "--no-root", map[string]string{".poetry/plugins/p.py": "x = 1\n"}, false},
		{"--no-root still resolves from a source in the tree", "--no-root", map[string]string{"pyproject.toml": project + "[[tool.poetry.source]]\nname = \"x\"\nurl = \"./wheels\"\n"}, false},
		{"--no-root still builds a path source", "--no-root", map[string]string{"poetry.lock": pathLock, "lib/pyproject.toml": lib, "lib/setup.py": setupPy}, false},
		{"--extras foo", "--extras foo", nil, false},
		{"-E foo", "-E foo", nil, false},
		{"--extras=foo", "--extras=foo", nil, false},
		{"--all-extras", "--all-extras", nil, false},
		{"--all-groups", "--all-groups", nil, false},
		{"--sync", "--sync", nil, false},
		{"--dry-run", "--dry-run", nil, false},
		{"--compile", "--compile", nil, false},
		{"--only-root", "--only-root", nil, false},
		{"unknown flag", "--no-root --frobnicate", nil, false},
		{"--only with no value", "--only", nil, false},
		{"--only= with no value", "--only=", nil, false},
		{"--with taking a flag as its value", "--with --all-extras", nil, false},
		{"--without= naming a bad group", "--without=,dev", nil, false},
		{"-nq clustered", "-nq", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"pyproject.toml": project, "poetry.lock": lockPoetry, "install.sh": "#!/bin/sh\npoetry install " + tt.args + "\n"}
			for k, v := range tt.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			r := resolveVersion(t, dir, "jinja2")
			if !r.Found || r.Match.Resolved != tt.want || r.Partiality.Complete != tt.want {
				t.Fatalf("jinja2 = %+v partiality %+v, want resolved and complete %v", r.Match, r.Partiality, tt.want)
			}
			if r := resolveVersion(t, dir, "PyJWT"); r.Found || r.Exhaustive != tt.want {
				t.Fatalf("PyJWT found %v exhaustive %v, want not found and exhaustive %v", r.Found, r.Exhaustive, tt.want)
			}
		})
	}
}

// TestResolveVersions_PoetryInstallGroups pins that a poetry.lock package resolves only when
// the poetry install puts it in place: a package only unselected groups or an extra pull in is
// found at no version, and the exhaustive claim stands.
func TestResolveVersions_PoetryInstallGroups(t *testing.T) {
	const (
		pyproject = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2==3.1.4\"]\n" +
			"[tool.poetry.group.dev.dependencies]\npytest = \"8.3.2\"\n" +
			"[tool.poetry.group.docs]\noptional = true\n[tool.poetry.group.docs.dependencies]\nsphinx = \"7.4.7\"\n"
		lock = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\ngroups = [\"main\"]\n\n" +
			"[[package]]\nname = \"pytest\"\nversion = \"8.3.2\"\ngroups = [\"dev\"]\n\n" +
			"[[package]]\nname = \"sphinx\"\nversion = \"7.4.7\"\ngroups = [\"docs\"]\n\n" +
			"[[package]]\nname = \"colorama\"\nversion = \"0.4.6\"\ngroups = [\"main\", \"dev\"]\n"
		mainOnlyProject = "[tool.poetry]\nname = \"app\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\njinja2 = \"3.1.4\"\n"
		legacyProject   = mainOnlyProject + "[tool.poetry.dev-dependencies]\npytest = \"8.3.2\"\n"
		categoryLock    = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\ncategory = \"main\"\noptional = false\n\n" +
			"[[package]]\nname = \"pytest\"\nversion = \"8.3.2\"\ncategory = \"dev\"\noptional = false\n"
		bareLock = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n\n[[package]]\nname = \"pytest\"\nversion = \"8.3.2\"\n"
	)
	all := []string{"jinja2", "pytest", "sphinx", "colorama"}
	tests := []struct {
		name     string
		files    map[string]string // over pyproject.toml and poetry.lock
		resolved []string          // the packages of all that resolve; every other one is found unresolved
	}{
		{"--only main leaves dev out, keeps what main shares with it", map[string]string{"install.sh": "poetry install --only main\n"}, []string{"jinja2", "colorama"}},
		{"--without dev", map[string]string{"install.sh": "poetry install --without dev\n"}, []string{"jinja2", "colorama"}},
		{"--only=main", map[string]string{"install.sh": "poetry install --only=main\n"}, []string{"jinja2", "colorama"}},
		{"--no-dev is --only main", map[string]string{"install.sh": "poetry install --no-dev\n"}, []string{"jinja2", "colorama"}},
		{"--with an optional group", map[string]string{"install.sh": "poetry install --with docs --without dev\n"}, []string{"jinja2", "sphinx", "colorama"}},
		{"bare install leaves an optional group out", map[string]string{"install.sh": "poetry install\n"}, []string{"jinja2", "pytest", "colorama"}},
		{"--only ignores --with", map[string]string{"install.sh": "poetry install --only main --with docs\n"}, []string{"jinja2", "colorama"}},
		{"--with a group as the manifest does not spell it", map[string]string{"install.sh": "poetry install --with Docs\n"}, []string{"jinja2", "pytest", "colorama"}},
		{"--without drops every spelling", map[string]string{"install.sh": "poetry install --without Dev\n"}, []string{"jinja2", "colorama"}},
		{"each surface's install must install it", map[string]string{"install.sh": "poetry install --with docs\n", "ci.sh": "poetry install --only main\n"}, []string{"jinja2", "colorama"}},
		{"a package only an extra pulls in", map[string]string{"install.sh": "poetry install --with docs\n",
			"poetry.lock": strings.Replace(lock, `groups = ["docs"]`, "groups = [\"docs\"]\noptional = true", 1)}, []string{"jinja2", "pytest", "colorama"}},
		{"every same-name entry must install it", map[string]string{"install.sh": "poetry install --with docs\n",
			"poetry.lock": lock + "\n" + "[[package]]\nname = \"sphinx\"\nversion = \"7.4.7\"\ngroups = [\"docs\"]\noptional = true\n"}, []string{"jinja2", "pytest", "colorama"}},
		{"an empty groups list", map[string]string{"install.sh": "poetry install --with docs\n",
			"poetry.lock": strings.Replace(lock, `groups = ["docs"]`, `groups = []`, 1)}, []string{"jinja2", "pytest", "colorama"}},
		{"a lock group the manifest does not declare", map[string]string{"install.sh": "poetry install --with docs\n",
			"poetry.lock": strings.Replace(lock, `groups = ["main"]`, `groups = ["main", "ghost"]`, 1)}, []string{"pytest", "sphinx", "colorama"}},
		{"poetry 1.x category, --only main", map[string]string{"install.sh": "poetry install --only main\n", "pyproject.toml": legacyProject, "poetry.lock": categoryLock}, []string{"jinja2"}},
		{"poetry 1.x category, --only dev", map[string]string{"install.sh": "poetry install --only dev\n", "pyproject.toml": legacyProject, "poetry.lock": categoryLock}, []string{"pytest"}},
		{"poetry 1.x category dev with no dev group declared", map[string]string{"install.sh": "poetry install\n",
			"pyproject.toml": mainOnlyProject, "poetry.lock": categoryLock}, []string{"jinja2"}},
		{"poetry 1.x category, bare install", map[string]string{"install.sh": "poetry install\n", "pyproject.toml": legacyProject, "poetry.lock": categoryLock}, []string{"jinja2", "pytest"}},
		{"no membership keys under a group flag", map[string]string{"install.sh": "poetry install --only main\n", "pyproject.toml": legacyProject, "poetry.lock": bareLock}, nil},
		{"no membership keys, every group installed", map[string]string{"install.sh": "poetry install\n", "pyproject.toml": legacyProject, "poetry.lock": bareLock}, []string{"jinja2", "pytest"}},
		{"no install script leaves the lock as it is", nil, all},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"pyproject.toml": pyproject, "poetry.lock": lock}
			for k, v := range tt.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			for _, name := range all {
				if !strings.Contains(files["poetry.lock"], "\""+name+"\"") {
					continue
				}
				want := slices.Contains(tt.resolved, name)
				r := resolveVersion(t, dir, name)
				if !r.Found || r.Match.Resolved != want || r.Exhaustive != true {
					t.Errorf("%s = %+v found %v exhaustive %v, want found, resolved %v, exhaustive", name, r.Match, r.Found, r.Exhaustive, want)
				}
			}
			if r := resolveVersion(t, dir, "PyJWT"); r.Found || !r.Exhaustive {
				t.Errorf("PyJWT found %v exhaustive %v, want not found and exhaustive", r.Found, r.Exhaustive)
			}
		})
	}
}
