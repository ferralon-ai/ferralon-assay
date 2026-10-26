package pythonanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	exUVLock = `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "flask" }]

[[package]]
name = "flask"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "jinja2" }]

[[package]]
name = "jinja2"
version = "3.1.4"
source = { registry = "https://pypi.org/simple" }
`
	exPyproject    = "[project]\nname = \"app\"\ndependencies = [\"flask>=3\"]\n"
	exDynPyproject = "[project]\nname = \"app\"\ndynamic = [\"dependencies\"]\n"
	exSetupCfgFile = "[metadata]\nname = app\n[options]\ninstall_requires = file: deps.txt\n"
)

// Exhaustive covers the whole build dir: a manifest the resolver skipped or never parses, an
// include it did not follow, a pyproject group its lock does not hold, or an installed copy of
// the coordinate each withholds it. Every row keeps a uv.lock that would otherwise prove PyJWT
// absent.
func TestResolveVersions_ExhaustiveInstallSurface(t *testing.T) {
	// nulAt pads a comment so a NUL lands at byte off, then puts rest on the next line.
	nulAt := func(off int, rest string) string { return "# " + strings.Repeat("x", off-2) + "\x00\n" + rest }
	// utf16 encodes ASCII s as UTF-16 behind its byte-order mark.
	utf16 := func(bigEndian bool, s string) string {
		var b strings.Builder
		if bigEndian {
			b.WriteString("\xfe\xff")
		} else {
			b.WriteString("\xff\xfe")
		}
		for _, c := range []byte(s) {
			if bigEndian {
				b.WriteByte(0)
				b.WriteByte(c)
			} else {
				b.WriteByte(c)
				b.WriteByte(0)
			}
		}
		return b.String()
	}
	// utf32LE encodes ASCII s as UTF-32LE behind its byte-order mark.
	utf32LE := func(s string) string {
		b := []byte("\xff\xfe\x00\x00")
		for _, c := range []byte(s) {
			b = append(b, c, 0, 0, 0)
		}
		return string(b)
	}
	// commentsTo is comment lines filling n characters.
	commentsTo := func(n int) string {
		line := "# " + strings.Repeat("x", 61) + "\r\n"
		return strings.Repeat(line, n/len(line)) + "#" + strings.Repeat("x", n%len(line)-2) + "\r\n"
	}
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"baseline: lock and pyproject", map[string]string{}, true},

		// Manifests and installed trees under directories the analyzer skips.
		{"requirements under build/", map[string]string{"build/tool/requirements.txt": "pyjwt==2.8.0\n"}, false},
		{"requirements under env/", map[string]string{"env/requirements.txt": "pyjwt==2.8.0\n"}, false},
		{"pyproject under a dot-dir", map[string]string{".github/tool/pyproject.toml": "[project]\nname = \"tool\"\ndependencies = [\"pyjwt\"]\n"}, false},
		{"site-packages dist-info", map[string]string{"venv/lib/python3.12/site-packages/PyJWT-2.8.0.dist-info/METADATA": "Name: PyJWT\n"}, false},
		{"dist-packages egg-info", map[string]string{"lib/dist-packages/PyJWT-2.8.0-py3.12.egg-info/PKG-INFO": "Name: PyJWT\n"}, false},
		{"site-packages holding only locked names", map[string]string{".venv/lib/python3.12/site-packages/flask-3.0.0.dist-info/METADATA": "Name: flask\n"}, true},
		{"stray egg-info", map[string]string{"src/PyJWT.egg-info/PKG-INFO": "Name: PyJWT\n"}, false},
		{"vendored wheel", map[string]string{"wheels/PyJWT-2.8.0-py3-none-any.whl": "x"}, false},
		{"vendored sdist", map[string]string{"vendor/pyjwt-2.8.0.tar.gz": "x"}, false},
		{"egg-link", map[string]string{"PyJWT.egg-link": "/src/pyjwt\n"}, false},
		{"wheel for another name", map[string]string{"wheels/flask-3.0.0-py3-none-any.whl": "x"}, true},

		// Install manifests the resolver never parses.
		{"requirements/ directory", map[string]string{"requirements/prod.txt": "pyjwt==2.8.0\n"}, false},
		{"dev-requirements.txt", map[string]string{"dev-requirements.txt": "pyjwt==2.8.0\n"}, false},
		{"requirements.in", map[string]string{"requirements.in": "pyjwt\n"}, false},
		{"Pipfile without a lock", map[string]string{"Pipfile": "[packages]\npyjwt = \"*\"\n"}, false},
		{"environment.yml", map[string]string{"environment.yml": "dependencies:\n  - pip:\n    - pyjwt\n"}, false},
		{"tox.ini with deps", map[string]string{"tox.ini": "[testenv]\ndeps = pyjwt\n"}, false},
		// tox installs the project into each env it makes, resolving its dependencies itself.
		{"tox.ini without deps", map[string]string{"tox.ini": "[tox]\nenvlist = py312\n"}, false},
		{"noxfile.py installing", map[string]string{"noxfile.py": "def tests(session):\n    session.install(\"pyjwt\")\n"}, false},
		{"MANIFEST.in", map[string]string{"MANIFEST.in": "include README.md\n"}, true},

		// Requirements includes.
		{"-r include not parsed", map[string]string{"requirements.txt": "-r base.txt\nflask==3.0.0\n", "base.txt": "pyjwt==2.8.0\n"}, false},
		{"-r include glued", map[string]string{"requirements.txt": "-rbase.txt\n", "base.txt": "pyjwt==2.8.0\n"}, false},
		{"--requirement= include", map[string]string{"requirements.txt": "--requirement=base.txt\n", "base.txt": "pyjwt==2.8.0\n"}, false},
		{"-c include missing", map[string]string{"requirements.txt": "-c pins.txt\nflask==3.0.0\n"}, false},
		{"-r include of a parsed manifest", map[string]string{"requirements.txt": "-r requirements-dev.txt\nflask==3.0.0\n", "requirements-dev.txt": "jinja2==3.1.4\n"}, false},
		{"-r include of a parsed manifest, hashed", map[string]string{"requirements.txt": "-r requirements-dev.txt\nflask==3.0.0 --hash=sha256:aaa\n", "requirements-dev.txt": "jinja2==3.1.4\n"}, true},

		// pyproject declarations outside [project].
		{"[dependency-groups] unlocked", map[string]string{"pyproject.toml": exPyproject + "[dependency-groups]\ndev = [\"pyjwt>=2\"]\n"}, false},
		{"[dependency-groups] locked, with include-group", map[string]string{"pyproject.toml": exPyproject + "[dependency-groups]\ndev = [\"jinja2\", {include-group = \"base\"}]\nbase = [\"flask\"]\n"}, true},
		{"[dependency-groups] unreadable entry", map[string]string{"pyproject.toml": exPyproject + "[dependency-groups]\ndev = [\"=bad\"]\n"}, false},
		{"[dependency-groups] include of an unknown group", map[string]string{"pyproject.toml": exPyproject + "[dependency-groups]\ndev = [\"jinja2\", {include-group = \"base\"}]\n"}, false},
		{"[dependency-groups] include cycle", map[string]string{"pyproject.toml": exPyproject + "[dependency-groups]\ndev = [\"jinja2\", {include-group = \"base\"}]\nbase = [\"flask\", {include-group = \"dev\"}]\n"}, false},
		{"[tool.uv] dev-dependencies unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.uv]\ndev-dependencies = [\"pyjwt\"]\n"}, false},
		{"[tool.poetry.dependencies] unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.poetry.dependencies]\npython = \"^3.12\"\npyjwt = \"^2\"\n"}, false},
		{"[tool.poetry.dependencies] locked", map[string]string{"pyproject.toml": exPyproject + "[tool.poetry.dependencies]\npython = \"^3.12\"\nflask = { version = \"^3\" }\n"}, true},
		{"[tool.poetry.group] unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.poetry.group.dev.dependencies]\npyjwt = \"^2\"\n"}, false},
		{"[tool.poetry.dev-dependencies] unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.poetry.dev-dependencies]\npyjwt = \"^2\"\n"}, false},
		{"[tool.pdm.dev-dependencies] unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.pdm.dev-dependencies]\ntest = [\"pyjwt\"]\n"}, false},
		{"[tool.hatch.envs] unlocked", map[string]string{"pyproject.toml": exPyproject + "[tool.hatch.envs.default]\ndependencies = [\"pyjwt\"]\n"}, false},

		// Requirement files named by setup.cfg "file:" and pyproject dynamic metadata.
		{"setup.cfg file: locked names", map[string]string{"setup.cfg": exSetupCfgFile, "deps.txt": "flask>=3\n"}, true},
		{"setup.cfg file: unlocked name", map[string]string{"setup.cfg": exSetupCfgFile, "deps.txt": "flask>=3\nrequests\n"}, false},
		{"setup.cfg file: missing", map[string]string{"setup.cfg": exSetupCfgFile}, false},
		{"dynamic dependencies from setuptools file, locked", map[string]string{"pyproject.toml": exDynPyproject + "[tool.setuptools.dynamic]\ndependencies = {file = [\"deps.txt\"]}\n", "deps.txt": "flask>=3\n"}, true},
		{"dynamic dependencies from setuptools file, unlocked", map[string]string{"pyproject.toml": exDynPyproject + "[tool.setuptools.dynamic]\ndependencies = {file = [\"deps.txt\"]}\n", "deps.txt": "requests\n"}, false},
		{"dynamic dependencies from setup.cfg beside it", map[string]string{"pyproject.toml": exDynPyproject, "setup.cfg": "[metadata]\nname = app\n[options]\ninstall_requires = flask>=3\n"}, true},
		{"dynamic dependencies from an unread hatchling hook", map[string]string{"pyproject.toml": "[build-system]\nbuild-backend = \"hatchling.build\"\n" + exDynPyproject, "setup.cfg": "[flake8]\nmax-line-length = 100\n"}, false},
		{"dynamic dependencies with no source", map[string]string{"pyproject.toml": exDynPyproject}, false},

		// setup.py and hatch_build.py are read only when their dependencies are literal.
		{"setup.py literal install_requires", map[string]string{"setup.py": "from setuptools import setup\nsetup(name=\"app\", install_requires=[\"flask>=3\"])\n"}, true},
		{"setup.py computed install_requires", map[string]string{"setup.py": "from setuptools import setup\nREQS = open(\"deps.txt\").read().split()\nsetup(name=\"app\", install_requires=REQS)\n"}, false},
		{"setup.py install_requires extended", map[string]string{"setup.py": "from setuptools import setup\ninstall_requires = [\"flask>=3\"]\ninstall_requires.append(\"pyjwt\")\nsetup(name=\"app\", install_requires=install_requires)\n"}, false},
		{"setup.py splatted options", map[string]string{"setup.py": "from setuptools import setup\nsetup(name=\"app\", **load_options())\n"}, false},
		{"setup.py literal extras_require, unlocked", map[string]string{"setup.py": "from setuptools import setup\nsetup(name=\"app\", extras_require={\"http\": [\"requests\"]})\n"}, false},
		{"setup.py literal extras_require, locked", map[string]string{"setup.py": "from setuptools import setup\nsetup(name=\"app\", extras_require={\"web\": [\"jinja2\"], \"all\": [\"flask\", \"jinja2\"]})\n"}, true},
		{"setup.py computed extras_require", map[string]string{"setup.py": "from setuptools import setup\nsetup(name=\"app\", extras_require=EXTRAS)\n"}, false},
		{"hatch_build.py", map[string]string{"hatch_build.py": "from hatchling.metadata.plugin.interface import MetadataHookInterface\n"}, false},

		// A NUL makes buildtree.Head report a file binary, but pip reads past one in a comment, so
		// requirement lines found by content are judged with the NUL removed or made a newline.
		{"requirement lines by content", map[string]string{"deps.pins": "pyjwt==2.8.0\n"}, false},
		{"requirement lines by content, NUL at byte 40", map[string]string{"deps.pins": nulAt(40, "pyjwt==2.8.0\n")}, false},
		{"requirement lines by content, NUL past byte 8000", map[string]string{"deps.pins": nulAt(8100, "pyjwt==2.8.0\n")}, false},
		{"requirement lines by content, NUL splitting the requirement", map[string]string{"deps.pins": "pyjwt\x00==2.8.0\n"}, false},
		{"requirement lines by content, NUL ending a comment", map[string]string{"deps.pins": "# pins\x00pyjwt==2.8.0\n"}, false},
		// pip decodes a requirements file by its byte-order mark; Windows PowerShell 5 writes
		// `pip freeze >` as UTF-16LE with one.
		{"requirement lines by content, UTF-16LE with a BOM", map[string]string{"deps.pins": utf16(false, "# pins\r\npyjwt==2.8.0\r\n")}, false},
		{"requirement lines by content, UTF-16BE with a BOM", map[string]string{"deps.pins": utf16(true, "pyjwt==2.8.0\n")}, false},
		{"requirement lines by content, UTF-8 BOM", map[string]string{"deps.pins": "\xef\xbb\xbfpyjwt==2.8.0\n"}, false},
		{"UTF-16LE text file without requirement lines", map[string]string{"notes": utf16(false, "pyjwt is not used here\n")}, true},
		// pip's UTF-16 decoder consumes a second byte-order mark.
		{"requirement lines by content, UTF-16LE with a doubled BOM", map[string]string{"deps.pins": "\xff\xfe" + utf16(false, "pyjwt==2.8.0\n")}, false},
		// A marked file is judged over its UTF-8 twin's head: HeadSize bytes of UTF-8 text, which
		// UTF-16 and UTF-32 spend more raw bytes on.
		{"requirement lines by content, UTF-16LE, first requirement at character 40000", map[string]string{"deps.pins": utf16(false, commentsTo(40000)+"pyjwt==2.8.0\r\n")}, false},
		{"requirement lines by content, UTF-32LE, first requirement at character 40000", map[string]string{"deps.pins": utf32LE(commentsTo(40000) + "pyjwt==2.8.0\r\n")}, false},
		{"UTF-8 BOM text file without requirement lines", map[string]string{"notes": "\xef\xbb\xbfpyjwt is not used here\n"}, true},
		{"binary file without requirement lines", map[string]string{"assets/logo.png": "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00"}, true},
		{"text file without requirement lines", map[string]string{"notes": "pyjwt is not used here\n"}, true},
		{"empty file", map[string]string{"deps.pins": ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"uv.lock": exUVLock, "pyproject.toml": exPyproject}
			for k, v := range tt.files {
				files[k] = v
			}
			r := resolveVersion(t, writeTree(t, files), "PyJWT")
			// An installed copy is a found match of its own (installedCopies), and so is an
			// unlocked pyproject declaration; no other row holds PyJWT anywhere.
			if r.Found && r.Match.Source != "site-packages" && (r.Match.Source != "pyproject.toml" || r.Match.Resolved) {
				t.Fatalf("PyJWT unexpectedly found: %+v", r.Match)
			}
			if r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v (partiality %+v)", r.Exhaustive, tt.want, r.Partiality)
			}
		})
	}
}

// B3: a script surface the version veto withholds on may install a package no manifest or
// lock read here names, so it withholds Exhaustive too; a kept form installs only what a read
// lock holds and does not. Every row keeps a uv.lock that would otherwise prove PyJWT absent.
func TestResolveVersions_ExhaustiveScriptInstall(t *testing.T) {
	const (
		docker  = "FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml uv.lock ./\nRUN "
		pdmLock = "[metadata]\ngroups = [\"default\"]\n\n[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\ndependencies = [\"jinja2>=3.1\"]\n\n[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
		poLock  = "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n\n[package.dependencies]\njinja2 = \">=3.1.2\"\n\n[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
	)
	uv := func(extra map[string]string) map[string]string {
		files := map[string]string{"pyproject.toml": exPyproject, "uv.lock": exUVLock}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"Dockerfile installs the coordinate after a locked sync", uv(map[string]string{"Dockerfile": docker + "uv sync --frozen && pip install pyjwt\n"}), false},
		{"shell script installs the coordinate", uv(map[string]string{"install.sh": "pip install pyjwt\n"}), false},
		{"Makefile installs the coordinate", uv(map[string]string{"Makefile": "install:\n\tpip install pyjwt\n"}), false},
		{"Dockerfile fetches over the lock, then syncs it", uv(map[string]string{"Dockerfile": docker + "curl -o uv.lock https://example.com/x && uv sync --frozen\n"}), false},
		{"Dockerfile copies an unplaced stage over the tree, then syncs", uv(map[string]string{"Dockerfile": "FROM python:3.12 AS builder\nRUN true\nFROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml uv.lock ./\nCOPY --from=builder /app .\nRUN uv sync --frozen\n"}), false},
		{"PowerShell installs the coordinate", uv(map[string]string{"install.ps1": "pip install pyjwt\n"}), false},
		{"Pipfile synced by pipenv", uv(map[string]string{"Pipfile": "[packages]\nflask = \"*\"\n", "Pipfile.lock": "{}\n", "Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY Pipfile Pipfile.lock ./\nRUN pipenv sync\n"}), false},

		// Kept forms install only what a read lock holds.
		{"Dockerfile uv sync --frozen", uv(map[string]string{"Dockerfile": docker + "uv sync --frozen\n"}), true},
		{"Dockerfile uv sync --locked", uv(map[string]string{"Dockerfile": docker + "uv sync --locked\n"}), true},
		{"Dockerfile pdm sync", map[string]string{"pyproject.toml": exPyproject, "pdm.lock": pdmLock, "Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml pdm.lock ./\nRUN pdm sync\n"}, true},
		{"Dockerfile poetry install", map[string]string{"pyproject.toml": exPyproject, "poetry.lock": poLock, "Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml poetry.lock ./\nRUN poetry install\n"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, tt.files), "PyJWT")
			if r.Found {
				t.Fatalf("PyJWT unexpectedly found: %+v", r.Match)
			}
			if r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v (partiality %+v)", r.Exhaustive, tt.want, r.Partiality)
			}
		})
	}
}

// pip resolves a requirements file's dependencies from the index, so a lock holding every name
// the file lists proves nothing about what pip installs past it. The file covers only in
// hash-checking mode (any --hash in the files one install reads, or --require-hashes), or when
// every install of it passes --no-deps and nothing installs it any other way.
func TestResolveVersions_ExhaustiveRequirementsInstall(t *testing.T) {
	const (
		h      = " --hash=sha256:aaa"
		docker = "FROM python:3.12\nWORKDIR /app\nCOPY . .\n"
	)
	uv := func(extra map[string]string) map[string]string {
		files := map[string]string{"pyproject.toml": exPyproject, "uv.lock": exUVLock}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"unhashed requirements.txt, no install", uv(map[string]string{"requirements.txt": "flask>=3\n"}), false},
		{"unhashed requirements file never installed", uv(map[string]string{"requirements-prod.txt": "flask==3.0.0\n"}), false},
		{"every line hashed", uv(map[string]string{"requirements.txt": "flask==3.0.0" + h + "\njinja2==3.1.4" + h + "\n"}), true},
		{"some lines hashed", uv(map[string]string{"requirements.txt": "flask==3.0.0" + h + "\njinja2==3.1.4\n"}), true},
		{"hash on a continued line", uv(map[string]string{"requirements.txt": "flask==3.0.0 \\\n    " + h + "\n"}), true},
		{"-r include of a hashed file", uv(map[string]string{"requirements.txt": "-r requirements-base.txt\n", "requirements-base.txt": "flask==3.0.0" + h + "\n"}), true},
		{"unhashed -r include inside a hashed file", uv(map[string]string{"requirements.txt": "-r requirements-base.txt\nflask==3.0.0" + h + "\n", "requirements-base.txt": "jinja2==3.1.4\n"}), true},
		{"unhashed -r include inside a hashed file, installed alone", uv(map[string]string{"requirements.txt": "-r requirements-base.txt\nflask==3.0.0" + h + "\n", "requirements-base.txt": "jinja2==3.1.4\n", "Dockerfile": docker + "RUN pip install -r requirements-base.txt\n"}), false},
		{"requirements file that only -r's a file with no pins", uv(map[string]string{"requirements-dev.txt": "-r requirements-empty.txt\n", "requirements-empty.txt": "# nothing pinned\n"}), false},
		{"--require-hashes option line", uv(map[string]string{"requirements.txt": "--require-hashes\nflask==3.0.0" + h + "\n"}), true},
		{"-c hashed constraints, unhashed requirement", uv(map[string]string{"requirements.txt": "-c requirements-constraints.txt\nflask>=3\n", "requirements-constraints.txt": "flask==3.0.0" + h + "\n"}), false},
		{"Dockerfile installs an unhashed requirements.txt", uv(map[string]string{"requirements.txt": "flask>=3\n", "Dockerfile": docker + "RUN pip install -r requirements.txt\n"}), false},

		{"install passes --require-hashes", uv(map[string]string{"requirements-prod.txt": "flask==3.0.0\n", "Dockerfile": docker + "RUN pip install --require-hashes -r requirements-prod.txt\n"}), true},
		{"every install passes --no-deps", uv(map[string]string{"requirements-prod.txt": "flask==3.0.0\n", "Dockerfile": docker + "RUN pip install --no-deps -r requirements-prod.txt\n"}), true},
		{"--no-deps install from a shell script", uv(map[string]string{"requirements-prod.txt": "flask==3.0.0\n", "install.sh": "pip install --no-deps -r requirements-prod.txt\n"}), true},
		{"--no-deps install, and a second without it", uv(map[string]string{"requirements-prod.txt": "flask==3.0.0\n", "Dockerfile": docker + "RUN pip install --no-deps -r requirements-prod.txt\nRUN pip install -r requirements-prod.txt\n"}), false},
		{"--no-deps install, and -r from a file installed with deps", uv(map[string]string{"requirements-prod.txt": "flask==3.0.0\n", "requirements-dev.txt": "-r requirements-prod.txt\n", "Dockerfile": docker + "RUN pip install --no-deps -r requirements-prod.txt\nRUN pip install -r requirements-dev.txt\n"}), false},
		{"--no-deps install, -r from a file installed --no-deps", uv(map[string]string{"requirements-prod.txt": "flask==3.0.0\n", "requirements-dev.txt": "-r requirements-prod.txt\n", "Dockerfile": docker + "RUN pip install --no-deps -r requirements-prod.txt\nRUN pip install --no-deps -r requirements-dev.txt\n"}), true},
		{"root requirements.txt under a Procfile, --no-deps in a Dockerfile", uv(map[string]string{"requirements.txt": "flask==3.0.0\n", "Procfile": "web: gunicorn app:app\n", "Dockerfile": docker + "RUN pip install --no-deps -r requirements.txt\n"}), false},
		{"requirements.txt installed --no-deps, no buildpack signal", uv(map[string]string{"requirements.txt": "flask==3.0.0\n", "Dockerfile": docker + "RUN pip install --no-deps -r requirements.txt\n"}), false},
		{"--no-deps install of a file setup.cfg also names", uv(map[string]string{"setup.cfg": "[metadata]\nname = app\n[options]\ninstall_requires = file: requirements-prod.txt\n", "requirements-prod.txt": "flask==3.0.0\n", "Dockerfile": docker + "RUN pip install --no-deps -r requirements-prod.txt\n"}), false},
		{"install passes --no-require-hashes", uv(map[string]string{"requirements.txt": "flask==3.0.0" + h + "\n", "Dockerfile": docker + "RUN pip install --no-require-hashes -r requirements.txt\n"}), false},
		{"--no-require-hashes option line in a hashed file", uv(map[string]string{"requirements.txt": "--no-require-hashes\nflask==3.0.0" + h + "\n"}), false},
		{"pip.conf copied in sets no-require-hashes", uv(map[string]string{"requirements.txt": "flask==3.0.0" + h + "\n", "docker/pip.conf": "[install]\nno-require-hashes = true\n", "Dockerfile": docker + "COPY docker/pip.conf /etc/pip.conf\n"}), false},
		{"--no-require-hashes second on an option line", uv(map[string]string{"requirements.txt": "--trusted-host pypi.org --no-require-hashes\nflask==3.0.0" + h + "\n"}), false},
		{"--no-require-hashes second on an option line in a nested file", uv(map[string]string{"requirements.txt": "-r requirements-base.txt\n", "requirements-base.txt": "--prefer-binary --no-require-hashes\nflask==3.0.0" + h + "\n"}), false},
		{"--no-require-hashes abbreviated on an option line", uv(map[string]string{"requirements.txt": "--trusted-host pypi.org --no-r\nflask==3.0.0" + h + "\n"}), false},
		{"pip.conf with the key capitalised", uv(map[string]string{"requirements.txt": "flask==3.0.0" + h + "\n", "docker/pip.conf": "[install]\nNo-Require-Hashes = 1\n"}), false},
		{"pip.conf with underscores", uv(map[string]string{"requirements.txt": "flask==3.0.0" + h + "\n", "docker/pip.conf": "[install]\nno_require_hashes = 1\n"}), false},
		{"pip.ini names no-require-hashes", uv(map[string]string{"requirements.txt": "flask==3.0.0" + h + "\n", "docker/pip.ini": "[install]\nno-require-hashes = 1\n"}), false},
		{"PIP.CONF names no-require-hashes", uv(map[string]string{"requirements.txt": "flask==3.0.0" + h + "\n", "docker/PIP.CONF": "[install]\nno-require-hashes = 1\n"}), false},
		{"pip.conf inside a nested .git directory", uv(map[string]string{"requirements.txt": "flask==3.0.0" + h + "\n", "vendor/.git/pip.conf": "[install]\nno-require-hashes = 1\n"}), false},
		{"option line --require-hashes with unhashed pins", uv(map[string]string{"requirements.txt": "--require-hashes\nflask==3.0.0\n"}), true},
		{"pip.conf that leaves hash mode alone", uv(map[string]string{"requirements.txt": "flask==3.0.0" + h + "\n", "docker/pip.conf": "[global]\ntimeout = 60\n", "Dockerfile": docker + "COPY docker/pip.conf /etc/pip.conf\n"}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, tt.files), "PyJWT")
			if r.Found {
				t.Fatalf("PyJWT unexpectedly found: %+v", r.Match)
			}
			if r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v (partiality %+v)", r.Exhaustive, tt.want, r.Partiality)
			}
		})
	}
	// The version path is unchanged: a requirements file that no longer covers still resolves.
	r := resolveVersion(t, writeTree(t, uv(map[string]string{"requirements.txt": "flask>=3\n"})), "jinja2")
	if !r.Found || !r.Match.Resolved {
		t.Fatalf("jinja2: found=%v %+v, want resolved", r.Found, r.Match)
	}
}

// A file installed only with --no-deps is refused only while every file that -r's it is refused
// too. The Exhaustive rows cannot pin this: an includer that is not refused withholds on its own
// check, so the includer test runs directly.
func TestReqInstalls_RefusedNeedsEveryIncluder(t *testing.T) {
	root := writeTree(t, map[string]string{
		"requirements-base.txt": "flask==3.0.0\n",
		"requirements-dev.txt":  "-r requirements-base.txt\n",
	})
	base, dev := filepath.Join(root, "requirements-base.txt"), filepath.Join(root, "requirements-dev.txt")
	tests := []struct {
		name     string
		devInstl pipInstall
		want     bool // base refused
	}{
		{"includer installed with dependencies", pipInstall{}, false},
		{"includer installed --no-deps", pipInstall{noDeps: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installs := pipInstalls{base: {{noDeps: true}}, dev: {tt.devInstl}}
			r := newReqInstalls(root, []string{base, dev}, installs)
			if got := r.refused(base); got != tt.want {
				t.Fatalf("refused(base) = %v, want %v", got, tt.want)
			}
		})
	}
}

// A pip.conf or pip.ini this cannot read, or a directory it cannot walk, may name
// no-require-hashes, so either counts as naming it. The Exhaustive rows cannot pin this: an
// unreadable file or directory withholds there on its own, so the check runs directly.
func TestPipConfigDisablesHashes_Unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads files whatever their mode")
	}
	tests := []struct {
		name string
		mode os.FileMode
		path string // the entry made unreadable
		file bool
	}{
		{"pip.conf that cannot be read", 0o000, "pip.conf", true},
		{"directory that cannot be walked", 0o000, "svc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, tt.path)
			if tt.file {
				if err := os.WriteFile(p, []byte("[global]\ntimeout = 60\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
			if pipConfigDisablesHashes(root) {
				t.Fatal("readable tree reported as naming no-require-hashes")
			}
			if err := os.Chmod(p, tt.mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
			if !pipConfigDisablesHashes(root) {
				t.Fatal("unreadable entry not counted as naming no-require-hashes")
			}
		})
	}
}

// A conda recipe's run requirements are installed by conda, which no Python lockfile records,
// and the resolver never reads a recipe, so any recipe withholds Exhaustive.
func TestResolveVersions_ExhaustiveCondaRecipe(t *testing.T) {
	const recipe = "package:\n  name: app\n  version: 0.1.0\nrequirements:\n  run:\n    - python\n    - pyjwt\n"
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"control: no recipe", map[string]string{}, true},
		{"meta.yaml", map[string]string{"meta.yaml": recipe}, false},
		{"meta.yml", map[string]string{"meta.yml": recipe}, false},
		{"recipe.yaml", map[string]string{"recipe.yaml": recipe}, false},
		{"recipe.yml", map[string]string{"recipe.yml": recipe}, false},
		{"conda.yaml", map[string]string{"conda.yaml": recipe}, false},
		{"conda.yml", map[string]string{"conda.yml": recipe}, false},
		{"nested recipe", map[string]string{"conda/recipe/meta.yaml": recipe}, false},
		{"META.YAML", map[string]string{"META.YAML": recipe}, false},
		{"Meta.yml", map[string]string{"Meta.yml": recipe}, false},
		{"Recipe.yaml", map[string]string{"Recipe.yaml": recipe}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"uv.lock": exUVLock, "pyproject.toml": exPyproject}
			for k, v := range tt.files {
				files[k] = v
			}
			r := resolveVersion(t, writeTree(t, files), "PyJWT")
			if r.Found {
				t.Fatalf("PyJWT unexpectedly found: %+v", r.Match)
			}
			if r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v (partiality %+v)", r.Exhaustive, tt.want, r.Partiality)
			}
		})
	}
}

// A symlinked directory leaving the build dir is not followed by the walk, so what it holds goes
// unread.
func TestResolveVersions_ExhaustiveSymlinkedDir(t *testing.T) {
	root := writeTree(t, map[string]string{"uv.lock": exUVLock, "pyproject.toml": exPyproject})
	elsewhere := writeTree(t, map[string]string{"requirements.txt": "pyjwt==2.8.0\n"})
	if r := resolveVersion(t, root, "PyJWT"); !r.Exhaustive {
		t.Fatalf("baseline not exhaustive")
	}
	if err := os.Symlink(elsewhere, filepath.Join(root, "tools")); err != nil {
		t.Fatal(err)
	}
	if r := resolveVersion(t, root, "PyJWT"); r.Exhaustive {
		t.Fatalf("Exhaustive with a symlinked directory")
	}
}

// Pipfile.lock sections are walked in sorted key order, so All and Match are identical across
// runs. Go randomizes map iteration, so an unsorted walk fails this within a few of the 64 runs.
func TestResolveVersions_PipfileLockWalkOrderDeterministic(t *testing.T) {
	const lock = `{"default": {"zeta": {"version": "==1.0.0"}, "requests": {"version": "==2.31.0"}, "alpha": {"version": "==1.0.0"}, "mid": {"version": "==2.0.0"}},
"develop": {"requests": {"version": "==2.32.3"}, "beta": {"version": "==3.0.0"}, "gamma": {"version": "==4.0.0"}}}`
	want := []string{"alpha@1.0.0", "mid@2.0.0", "requests@2.31.0", "zeta@1.0.0", "beta@3.0.0", "gamma@4.0.0", "requests@2.32.3"}
	dir := writeTree(t, map[string]string{"Pipfile.lock": lock})
	first := resolveVersion(t, dir, "requests").Match
	for i := 0; i < 64; i++ {
		r := resolveVersion(t, dir, "requests")
		got := make([]string, 0, len(r.All))
		for _, d := range r.All {
			got = append(got, d.Coordinate+"@"+d.Version)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d: All = %v, want %v", i, got, want)
		}
		if !reflect.DeepEqual(r.Match, first) {
			t.Fatalf("run %d: Match = %+v, first run %+v", i, r.Match, first)
		}
	}
}
