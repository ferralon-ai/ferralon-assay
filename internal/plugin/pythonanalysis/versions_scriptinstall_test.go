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

// ensurepip installs the pip its interpreter bundles, and setuptools before Python 3.12, so the
// allowed form withholds those two coordinates alone; any other form withholds every pin.
func TestResolveVersions_Ensurepip(t *testing.T) {
	const reqs = "jinja2==3.1.4\npip==24.0\nsetuptools==69.0.0\n"
	tests := []struct {
		name  string
		files map[string]string
		seeds bool // whether the line withholds pip and setuptools alone: jinja2 resolves
	}{
		{"python -m ensurepip", map[string]string{"install.sh": "python -m ensurepip\n"}, true},
		{"--upgrade", map[string]string{"install.sh": "python3 -m ensurepip --upgrade\n"}, true},
		{"every reviewed flag", map[string]string{"install.sh": "python3.11 -m ensurepip -U --default-pip --user -v --verbose\n"}, true},
		{"--altinstall", map[string]string{"install.sh": "python3.11 -m ensurepip --upgrade --altinstall\n"}, true},
		{"Dockerfile", map[string]string{"Dockerfile": "FROM python:3.11\nRUN python -m ensurepip --upgrade\n"}, true},

		{"--root", map[string]string{"install.sh": "python -m ensurepip --root /opt/py\n"}, false},
		{"another argument", map[string]string{"install.sh": "python -m ensurepip jinja2\n"}, false},
		{"attached -m", map[string]string{"install.sh": "python -mensurepip\n"}, false},
		{"pip config in the tree", map[string]string{"pip.conf": "[global]\n", "install.sh": "python -m ensurepip\n"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"requirements.txt": reqs}
			for k, v := range tt.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			if r := resolveVersion(t, dir, "jinja2"); !r.Found || r.Match.Resolved != tt.seeds || r.Partiality.Complete != tt.seeds {
				t.Fatalf("jinja2 = %+v partiality %+v, want resolved and complete %v", r.Match, r.Partiality, tt.seeds)
			}
			for _, c := range []string{"pip", "setuptools"} {
				if r := resolveVersion(t, dir, c); !r.Found || r.Match.Resolved || r.Partiality.Complete || r.MatchesComplete {
					t.Fatalf("%s = %+v, want found, unresolved and partial", c, r)
				}
			}
		})
	}
}

// Under a lock that covers the build, ensurepip leaves absence proven for every coordinate but
// the two it installs, and declares both to the import resolver.
func TestResolveVersions_EnsurepipExhaustive(t *testing.T) {
	dir := writeTree(t, map[string]string{"pyproject.toml": exPyproject, "uv.lock": exUVLock,
		"Dockerfile": "FROM python:3.11\nWORKDIR /app\nCOPY pyproject.toml uv.lock ./\nRUN python -m ensurepip --upgrade && uv sync --frozen\n"})
	if r := resolveVersion(t, dir, "PyJWT"); r.Found || !r.Exhaustive {
		t.Fatalf("PyJWT = found %v exhaustive %v, want absent and exhaustive", r.Found, r.Exhaustive)
	}
	for _, c := range []string{"pip", "setuptools"} {
		if r := resolveVersion(t, dir, c); r.Found || r.Exhaustive {
			t.Fatalf("%s = found %v exhaustive %v, want absent and not exhaustive", c, r.Found, r.Exhaustive)
		}
	}
	names, complete, read := declaredDistributions(dir)
	if !names["pip"] || !names["setuptools"] || !complete || !read {
		t.Fatalf("declaredDistributions = %v complete %v read %v, want pip and setuptools declared, complete and read", names, complete, read)
	}
}

// mypy --install-types runs pip on the stub packages it finds missing, as does a mypy config
// that sets install_types, so either withholds every pin. A plain mypy run does not.
func TestResolveVersions_MypyInstallTypes(t *testing.T) {
	const reqs = "jinja2==3.1.4\n"
	tests := []struct {
		name  string
		files map[string]string
		want  bool // jinja2 resolved
	}{
		{"mypy --install-types", map[string]string{"install.sh": "mypy --install-types --non-interactive .\n"}, false},
		{"python -m mypy", map[string]string{"Makefile": "lint:\n\tpython -m mypy --install-types --non-interactive src\n"}, false},
		{"dmypy", map[string]string{"install.sh": "dmypy run -- --install-types --non-interactive .\n"}, false},
		{"CI step", map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: mypy --install-types --non-interactive .\n"}, false},
		{"mypy.ini install_types", map[string]string{"mypy.ini": "[mypy]\ninstall_types = True\nnon_interactive = True\n", "install.sh": "mypy .\n"}, false},
		{"setup.cfg install_types", map[string]string{"setup.cfg": "[mypy]\ninstall_types = True\n", "install.sh": "mypy .\n"}, false},
		{"pyproject [tool.mypy]", map[string]string{"pyproject.toml": "[tool.mypy]\ninstall_types = true\n", "install.sh": "mypy .\n"}, false},
		{"--config-file to a .cfg", map[string]string{"config/types.cfg": "[mypy]\ninstall_types = True\n", "install.sh": "mypy --config-file config/types.cfg .\n"}, false},
		{"config, dmypy", map[string]string{".mypy.ini": "[mypy]\ninstall_types = True\n", "install.sh": "dmypy run -- .\n"}, false},
		{"abbreviated --install", map[string]string{"install.sh": "mypy --install --non-interactive .\n"}, false},
		{"abbreviated --install-type", map[string]string{"install.sh": "mypy --install-type --non-interactive .\n"}, false},
		{"abbreviated --ins", map[string]string{"install.sh": "mypy --ins --non-interactive .\n"}, false},
		{"config, -mmypy", map[string]string{"mypy.ini": "[mypy]\ninstall_types = True\n", "install.sh": "python -mmypy .\n"}, false},
		{"config, -Immypy", map[string]string{"mypy.ini": "[mypy]\ninstall_types = True\n", "install.sh": "python3 -Immypy .\n"}, false},
		{"config, colon delimiter", map[string]string{"mypy.ini": "[mypy]\ninstall_types: yes\n", "install.sh": "mypy .\n"}, false},
		{"config, value on the next line", map[string]string{"mypy.ini": "[mypy]\ninstall_types =\n    1\n", "install.sh": "mypy .\n"}, false},
		{"user config copied from the tree", map[string]string{"docker/.config/mypy/config": "[mypy]\ninstall_types = True\n", "Dockerfile": "FROM python:3.12\nCOPY docker/.config /root/.config\nRUN mypy .\n"}, false},
		{"--config-file to a .conf", map[string]string{"ci/typecheck.conf": "[mypy]\ninstall_types = True\n", "install.sh": "mypy --config-file ci/typecheck.conf .\n"}, false},
		{".conf in the tree", map[string]string{"ci/typecheck.conf": "[mypy]\ninstall_types = True\n", "install.sh": "MYPYRC=1 mypy .\n"}, false},
		{"renamed config copied to ~/.mypy.ini", map[string]string{"docker/typecheck-rc": "[mypy]\ninstall_types = True\n", "Dockerfile": "FROM python:3.12\nCOPY docker/typecheck-rc /root/.mypy.ini\nRUN mypy .\n"}, false},
		{"--config-file outside the tree", map[string]string{"install.sh": "mypy --config-file /etc/ci/typecheck .\n"}, false},
		{"config named in one surface, mypy run in another", map[string]string{"Dockerfile": "FROM python:3.12\nCOPY docker/rc /root/.config/mypy/config\n", "Makefile": "lint:\n\tmypy src\n"}, false},

		// Guards.
		{"plain mypy", map[string]string{"install.sh": "mypy --strict .\n"}, true},
		{"mypy config without install_types", map[string]string{"mypy.ini": "[mypy]\nstrict = True\n", "install.sh": "mypy .\n"}, true},
		{"install_types config, no mypy run", map[string]string{"mypy.ini": "[mypy]\ninstall_types = True\n", "install.sh": "pytest\n"}, true},
		{"install_types off", map[string]string{"mypy.ini": "[mypy]\ninstall_types = False\n", "install.sh": "mypy .\n"}, true},
		{"--no-install-types", map[string]string{".github/workflows/mypy.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: mypy --no-install-types .\n"}, true},
		{"--config-file, no mypy run", map[string]string{"install.sh": "yamllint --config-file ci/yamllint.yml .\npytest\n"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"requirements.txt": reqs}
			for k, v := range tt.files {
				files[k] = v
			}
			r := resolveVersion(t, writeTree(t, files), "jinja2")
			if !r.Found || r.Match.Resolved != tt.want || r.Partiality.Complete != tt.want {
				t.Fatalf("jinja2 = %+v partiality %+v, want resolved and complete %v", r.Match, r.Partiality, tt.want)
			}
		})
	}
}
