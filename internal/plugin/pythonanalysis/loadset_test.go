package pythonanalysis

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// loadsetLock is a uv workspace with one member, app. Runtime: requests (→ urllib3, idna),
// sqlalchemy, litellm, click, django. Dev group: black (→ pathspec), pytest (→ pluggy),
// pytest-cov (→ pytest, coverage), django-debug-toolbar. Unrequested extra pg: asyncpg.
const loadsetLock = `version = 1
requires-python = ">=3.11"

[manifest]
members = ["app"]

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
    { name = "sqlalchemy" },
    { name = "litellm" },
    { name = "click" },
    { name = "django" },
]

[package.optional-dependencies]
pg = [{ name = "asyncpg" }]

[package.dev-dependencies]
dev = [
    { name = "black" },
    { name = "pytest" },
    { name = "pytest-cov" },
    { name = "django-debug-toolbar" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "urllib3" }, { name = "idna" }]

[[package]]
name = "urllib3"
version = "2.2.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "idna"
version = "3.7"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "sqlalchemy"
version = "2.0.30"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "litellm"
version = "1.40.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "click"
version = "8.1.7"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "django"
version = "5.0.6"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "asyncpg"
version = "0.29.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "black"
version = "24.4.2"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pathspec" }]

[[package]]
name = "pathspec"
version = "0.12.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.2.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pluggy" }]

[[package]]
name = "pluggy"
version = "1.5.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest-cov"
version = "5.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pytest" }, { name = "coverage" }]

[[package]]
name = "coverage"
version = "7.5.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "django-debug-toolbar"
version = "4.4.2"
source = { registry = "https://pypi.org/simple" }
`

const devAssumption = "assumes dev/tooling groups are not installed at runtime"

// withDevDists returns the uv workspace with extra dev-group distributions locked.
func withDevDists(files map[string]string, dists map[string]string) map[string]string {
	lock := loadsetLock
	for _, n := range sortedMapKeys(dists) {
		lock = strings.Replace(lock, "dev = [\n", "dev = [\n    { name = \""+n+"\" },\n", 1)
		lock += "\n[[package]]\nname = \"" + n + "\"\nversion = \"" + dists[n] + "\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
	}
	out := withLock(files)
	out["uv.lock"] = lock
	return out
}

// twoCopiesLock locks foo twice: 2.0.0 for app at runtime (pulling in bar) and 1.0.0 for app's
// dev group. The runtime copy is listed first, so a reader that keeps one copy per name keeps
// the dev copy and loses bar's edge.
const twoCopiesLock = `version = 1

[manifest]
members = ["app"]

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests" }, { name = "foo", version = "2.0.0" }]

[package.dev-dependencies]
dev = [{ name = "foo", version = "1.0.0" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "foo"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "bar" }]

[[package]]
name = "foo"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "bar"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
`

// withClosureLock returns the uv workspace where django-debug-toolbar (dev) depends on
// sqlparse and asyncpg (extra pg) depends on async-timeout, neither imported anywhere.
func withClosureLock(files map[string]string) map[string]string {
	lock := strings.Replace(loadsetLock, "name = \"django-debug-toolbar\"\nversion = \"4.4.2\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
		"name = \"django-debug-toolbar\"\nversion = \"4.4.2\"\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [{ name = \"sqlparse\" }]\n", 1)
	lock = strings.Replace(lock, "name = \"asyncpg\"\nversion = \"0.29.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
		"name = \"asyncpg\"\nversion = \"0.29.0\"\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [{ name = \"async-timeout\" }]\n", 1)
	lock += "\n[[package]]\nname = \"sqlparse\"\nversion = \"0.5.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
	lock += "\n[[package]]\nname = \"async-timeout\"\nversion = \"4.0.3\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
	out := withLock(files)
	out["uv.lock"] = lock
	return out
}

const devPoetryLock = "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\ngroups = [\"main\"]\n\n[[package]]\nname = \"black\"\nversion = \"24.4.2\"\ngroups = [\"dev\"]\n"

// withLock returns a tree of the uv workspace plus files.
func withLock(files map[string]string) map[string]string {
	out := map[string]string{"uv.lock": loadsetLock, "app/__init__.py": "", "app/main.py": "import requests\n"}
	for k, v := range files {
		out[k] = v
	}
	return out
}

func reachFor(t *testing.T, files map[string]string, pkg string) plugin.ReachabilityResult {
	t.Helper()
	dir := writeTree(t, files)
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Package: pkg})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	return res
}

func scopedFor(p plugin.Partiality, purl string) *plugin.ScopedReason {
	for i := range p.Scoped {
		if p.Scoped[i].Package == purl {
			return &p.Scoped[i]
		}
	}
	return nil
}

func TestLoadSet_PackageNotLoaded(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		pkg     string
		refute  bool
		detail  []string // substrings the Detail must carry when refuted
		purl    string   // Refutation.Package when refuted
		reason  bool     // the run-wide dynamic_import reason must be present
		scoped  string   // a scoped reason with this Package must be present
		noScope bool     // the scoped reason above must not target pkg
		fpOnly  bool     // every scoped reason must target first-party code only
	}{
		{
			name:  "dev-group distribution no runtime root loads refutes",
			files: withLock(nil), pkg: "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black",
			detail: []string{"outside the runtime install", "app dependency group dev", devAssumption, "uv.lock"},
		},
		{
			name:  "import-binding root loads a dev distribution",
			files: withLock(map[string]string{"app/fmt.py": "import black\n"}), pkg: "pkg:pypi/black@24.4.2",
		},
		{
			name:  "function-local from-import is a root",
			files: withLock(map[string]string{"app/fmt.py": "def f(s):\n    from black import format_str\n    return format_str(s)\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "INSTALLED_APPS string root loads the app by import name",
			files: withLock(map[string]string{"app/settings.py": "INSTALLED_APPS = [\n    \"django.contrib.admin\",\n    \"debug_toolbar\",\n]\n"}),
			pkg:   "pkg:pypi/django-debug-toolbar@4.4.2",
		},
		{
			name:  "INSTALLED_APPS without the app leaves it refuted",
			files: withLock(map[string]string{"app/settings.py": "INSTALLED_APPS = [\"django.contrib.admin\"]\n"}),
			pkg:   "pkg:pypi/django-debug-toolbar@4.4.2", refute: true, purl: "pkg:pypi/django-debug-toolbar",
		},
		{
			name:  "console_scripts entry point is a root",
			files: withLock(map[string]string{"pyproject.toml": "[project]\nname = \"app\"\n\n[project.scripts]\nfmt = \"black:patched_main\"\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "closure edge: a dependency of a loaded distribution is loaded",
			files: withLock(map[string]string{"app/fmt.py": "import black\n"}), pkg: "pkg:pypi/pathspec@0.12.1",
		},
		{
			name:  "closure edge absent: dependency reachable only from dev tooling refutes",
			files: withLock(nil), pkg: "pkg:pypi/pathspec@0.12.1", refute: true, purl: "pkg:pypi/pathspec",
			detail: []string{"app dependency group dev"},
		},
		{
			name: "pytest plugin used only by test code is not loaded",
			files: withLock(map[string]string{
				"conftest.py":         "import pytest_cov\n",
				"tests/test_main.py":  "import pytest\nfrom app import main\n",
				"app/test_helpers.py": "import pytest\n",
			}),
			pkg: "pkg:pypi/pytest-cov@5.0.0", refute: true, purl: "pkg:pypi/pytest-cov",
		},
		{
			name:  "enumerating loader marks its drivers loaded, with no scoped limit",
			files: withLock(map[string]string{"app/db.py": "import sqlalchemy\n"}), pkg: "pkg:pypi/asyncpg@0.29.0",
			fpOnly: true,
		},
		{
			name:  "unbounded loader marks the runtime install loaded, so a dev distribution still refutes",
			files: withLock(map[string]string{"app/llm.py": "import litellm\n"}), pkg: "pkg:pypi/black@24.4.2",
			refute: true, purl: "pkg:pypi/black", fpOnly: true,
			detail: []string{"loaders expanded: litellm;"},
		},
		{
			name:  "SQLAlchemy URL driver in a config is a root",
			files: withLock(map[string]string{"config.yaml": "db:\n  url: postgresql+asyncpg://u:p@db/app\n"}),
			pkg:   "pkg:pypi/asyncpg@0.29.0",
		},
		{
			name:  "unrequested extra with no root refutes as optional",
			files: withLock(nil), pkg: "pkg:pypi/asyncpg@0.29.0", refute: true, purl: "pkg:pypi/asyncpg",
			detail: []string{"app[pg] extra", devAssumption},
		},
		{
			name:  "unscoped non-literal import clears complete",
			files: withLock(map[string]string{"app/plug.py": "import importlib\n\ndef load(name):\n    return importlib.import_module(name)\n"}),
			pkg:   "pkg:pypi/black@24.4.2", reason: true,
		},
		{
			name: "prefix into first-party is scoped and the dev distribution still refutes",
			files: withLock(map[string]string{
				"app/plugins/__init__.py": "",
				"app/plug.py":             "import importlib\n\ndef load(name):\n    return importlib.import_module(\"app.plugins.\" + name)\n",
			}),
			pkg: "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black", fpOnly: true,
		},
		{
			name:  "prefix into a distribution loads it",
			files: withLock(map[string]string{"app/plug.py": "import importlib\n\ndef load(n):\n    return importlib.import_module(f\"black.{n}\")\n"}),
			pkg:   "pkg:pypi/black@24.4.2", scoped: "pkg:pypi/black",
		},
		{
			name:  "relative import_module with package=__package__ resolves first-party",
			files: withLock(map[string]string{"app/plug.py": "import importlib\nm = importlib.import_module(\".main\", package=__package__)\n"}),
			pkg:   "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black",
		},
		{
			name:  "aliased import_module with a computed name blocks",
			files: withLock(map[string]string{"app/plug.py": "from importlib import import_module as im\n\ndef load(x):\n    return im(x)\n"}),
			pkg:   "pkg:pypi/black@24.4.2", reason: true,
		},
		{
			name:  "spec_from_file_location blocks",
			files: withLock(map[string]string{"app/plug.py": "import importlib.util\n\ndef load(p):\n    spec = importlib.util.spec_from_file_location(\"m\", p)\n    return importlib.util.module_from_spec(spec)\n"}),
			pkg:   "pkg:pypi/black@24.4.2", reason: true,
		},
		{
			name:  "runpy.run_path blocks",
			files: withLock(map[string]string{"app/plug.py": "import runpy\n\ndef go(p):\n    runpy.run_path(p)\n"}),
			pkg:   "pkg:pypi/black@24.4.2", reason: true,
		},
		{
			name:  "getattr with a computed name on importlib blocks",
			files: withLock(map[string]string{"app/plug.py": "import importlib\n\ndef go(n, m):\n    return getattr(importlib, n)(m)\n"}),
			pkg:   "pkg:pypi/black@24.4.2", reason: true,
		},
		{
			name:  "getattr with a computed name on a distribution module is scoped to its closure",
			files: withLock(map[string]string{"app/plug.py": "import requests\n\ndef go(n):\n    return getattr(requests, n)\n"}),
			pkg:   "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black", scoped: "pkg:pypi/requests", noScope: true,
		},
		{
			name:  "exec blocks",
			files: withLock(map[string]string{"app/plug.py": "def run(src):\n    exec(src)\n"}),
			pkg:   "pkg:pypi/black@24.4.2", reason: true,
		},
		{
			name:  "eval blocks",
			files: withLock(map[string]string{"app/plug.py": "def run(src):\n    return eval(src)\n"}),
			pkg:   "pkg:pypi/black@24.4.2", reason: true,
		},
		{
			name:  "compile blocks",
			files: withLock(map[string]string{"app/plug.py": "def run(src):\n    return compile(src, \"x\", \"exec\")\n"}),
			pkg:   "pkg:pypi/black@24.4.2", reason: true,
		},
		{
			name:  "star import from a distribution is scoped to its closure",
			files: withLock(map[string]string{"app/plug.py": "from requests import *\n"}),
			pkg:   "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black", scoped: "pkg:pypi/requests", noScope: true,
		},
		{
			name:  "star import from an unmapped module blocks",
			files: withLock(map[string]string{"app/plug.py": "from nowhere_known import *\n"}),
			pkg:   "pkg:pypi/black@24.4.2", reason: true,
		},
		{
			name:  "dynamic loads in test code are not roots and do not block",
			files: withLock(map[string]string{"tests/test_plug.py": "def t(src):\n    exec(src)\n"}),
			pkg:   "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black",
		},
		{
			name:  "unmapped import clears complete",
			files: withLock(map[string]string{"app/x.py": "import nowhere_known\n"}), pkg: "pkg:pypi/black@24.4.2",
		},
		{
			name:  "runtime distribution no root loads is class (ii): not refuted under A",
			files: withLock(nil), pkg: "pkg:pypi/click@8.1.7",
		},
		{
			name:  "version not locked does not refute",
			files: withLock(nil), pkg: "pkg:pypi/black@23.1.0",
		},
		{
			name:  "workspace member does not refute",
			files: withLock(nil), pkg: "pkg:pypi/app@0.1.0",
		},
		{
			name:  "empty Package does not refute",
			files: withLock(nil), pkg: "",
		},
		{
			name:  "PEP 503 variant of the admitted name refutes under the normalized PURL",
			files: withLock(nil), pkg: "pkg:pypi/Pytest_Cov@5.0.0", refute: true, purl: "pkg:pypi/pytest-cov",
		},
		{
			name:  "PEP 503 variant in an import matches the distribution",
			files: withLock(map[string]string{"app/x.py": "import Django_Debug_Toolbar\n"}), pkg: "pkg:pypi/django-debug-toolbar@4.4.2",
		},
		{
			name:  "advisory spelling PyJWT refutes the dev-only pyjwt under its PEP 503 name",
			files: withDevDists(nil, map[string]string{"pyjwt": "2.8.0"}), pkg: "pkg:pypi/PyJWT@2.8.0",
			refute: true, purl: "pkg:pypi/pyjwt",
		},
		{
			name:  "advisory spelling PyJWT does not refute pyjwt a runtime requirements file pins as PyJWT",
			files: withDevDists(map[string]string{"requirements.txt": "PyJWT==2.8.0\n"}, map[string]string{"pyjwt": "2.8.0"}),
			pkg:   "pkg:pypi/PyJWT@2.8.0",
		},
		{
			name:  "advisory spelling python_multipart refutes the dev-only python-multipart under its PEP 503 name",
			files: withDevDists(nil, map[string]string{"python-multipart": "0.0.9"}), pkg: "pkg:pypi/python_multipart@0.0.9",
			refute: true, purl: "pkg:pypi/python-multipart",
		},
		{
			name:  "advisory spelling python_multipart does not refute python-multipart a runtime import loads",
			files: withDevDists(map[string]string{"app/upload.py": "import python_multipart\n"}, map[string]string{"python-multipart": "0.0.9"}),
			pkg:   "pkg:pypi/python_multipart@0.0.9",
		},
		{
			name:  "dev-group copy at the admitted version plus a runtime copy of the same name does not refute",
			files: map[string]string{"uv.lock": twoCopiesLock, "app/__init__.py": "", "app/main.py": "import requests\n"},
			pkg:   "pkg:pypi/foo@1.0.0",
		},
		{
			name:  "a dependency only the runtime copy of a twice-locked name pulls in is runtime",
			files: map[string]string{"uv.lock": twoCopiesLock, "app/__init__.py": "", "app/main.py": "import requests\n"},
			pkg:   "pkg:pypi/bar@1.0.0",
		},
		{
			name: "the project's own distribution never refutes, even locked in a dev group",
			files: map[string]string{
				"pyproject.toml": "[project]\nname = \"My_App\"\nversion = \"0.1.0\"\n",
				"pdm.lock":       "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\ngroups = [\"default\"]\n\n[[package]]\nname = \"my-app\"\nversion = \"0.1.0\"\ngroups = [\"dev\"]\n",
				"app.py":         "import requests\n",
			},
			pkg: "pkg:pypi/my-app@0.1.0",
		},
		{
			name:  "non-dev requirements file naming a dev distribution puts it in the runtime install",
			files: withLock(map[string]string{"requirements.txt": "black==24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2",
		},
		{
			name:  "dev requirements file does not",
			files: withLock(map[string]string{"requirements-dev.txt": "black==24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2",
			refute: true, purl: "pkg:pypi/black",
		},
		{
			name:  "no lockfile does not refute",
			files: map[string]string{"requirements.txt": "black==24.4.2\n", "app.py": "import requests\n"},
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name: "edgeless Pipfile.lock does not refute",
			files: map[string]string{
				"Pipfile.lock": `{"_meta": {"pipfile-spec": 6}, "default": {"requests": {"version": "==2.31.0"}}, "develop": {"black": {"version": "==24.4.2"}}}`,
				"app.py":       "import requests\n",
			},
			pkg: "pkg:pypi/black@24.4.2",
		},
		{
			name: "poetry lock with groups refutes a dev-only distribution",
			files: map[string]string{
				"poetry.lock": "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\ngroups = [\"main\"]\n\n[[package]]\nname = \"black\"\nversion = \"24.4.2\"\ngroups = [\"dev\"]\n",
				"app.py":      "import requests\n",
			},
			pkg: "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black", detail: []string{"poetry group dev"},
		},
		{
			name: "poetry lock without groups or category cannot tell runtime from dev",
			files: map[string]string{
				"poetry.lock": "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[[package]]\nname = \"black\"\nversion = \"24.4.2\"\n",
				"app.py":      "import requests\n",
			},
			pkg: "pkg:pypi/black@24.4.2",
		},
		{
			name: "pdm lock groups refute a dev-only distribution",
			files: map[string]string{
				"pdm.lock": "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\ngroups = [\"default\"]\n\n[[package]]\nname = \"black\"\nversion = \"24.4.2\"\ngroups = [\"lint\"]\n",
				"app.py":   "import requests\n",
			},
			pkg: "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black", detail: []string{"pdm group lint"},
		},
		{
			name:  "Dockerfile that keeps dev dependencies blocks class (i)",
			files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nRUN uv sync \\\n    --frozen\nCMD [\"python\", \"-m\", \"app.main\"]\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "Dockerfile that drops dev dependencies does not",
			files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nRUN uv sync --frozen --no-dev\nCMD [\"uv\", \"run\", \"--no-sync\", \"app\"]\n"}),
			pkg:   "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black",
		},
		{
			name:  "test CI install is not a production install",
			files: withLock(map[string]string{".github/workflows/ci.yml": "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    environment: test\n    steps:\n      - run: uv sync\n"}),
			pkg:   "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black",
		},
		{
			name:  "deploy-environment job in a generically named workflow is a production install",
			files: withLock(map[string]string{".github/workflows/ci.yml": "name: CI\non: [push]\njobs:\n  ship:\n    runs-on: ubuntu-latest\n    environment:\n      name: production\n    steps:\n      - run: |\n          uv sync\n          uv run app\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "build-push job in a generically named workflow is a production install",
			files: withLock(map[string]string{".github/workflows/ci.yml": "name: CI\non: [push]\njobs:\n  image:\n    runs-on: ubuntu-latest\n    steps:\n      - run: poetry install\n      - uses: docker/build-push-action@v6\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "deploy-named workflow is a production install",
			files: withLock(map[string]string{".github/workflows/deploy.yml": "on: [push]\njobs:\n  go:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pip install -r requirements-dev.txt\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "INSTALLED_APPS string root brings the app's lockfile closure into the load set",
			files: withClosureLock(map[string]string{"app/settings.py": "INSTALLED_APPS = [\n    \"django.contrib.admin\",\n    \"debug_toolbar\",\n]\n"}),
			pkg:   "pkg:pypi/sqlparse@0.5.0",
		},
		{
			name:  "the app's dependency refutes when no settings string names the app",
			files: withClosureLock(map[string]string{"app/settings.py": "INSTALLED_APPS = [\"django.contrib.admin\"]\n"}),
			pkg:   "pkg:pypi/sqlparse@0.5.0", refute: true, purl: "pkg:pypi/sqlparse",
		},
		{
			name:  "SQLAlchemy URL driver in a config file brings the driver's closure in",
			files: withClosureLock(map[string]string{"app/config.yaml": "database:\n  url: postgresql+asyncpg://app@db/app\n"}),
			pkg:   "pkg:pypi/async-timeout@4.0.3",
		},
		{
			name:  "the driver's dependency refutes when no URL names the driver",
			files: withClosureLock(nil),
			pkg:   "pkg:pypi/async-timeout@4.0.3", refute: true, purl: "pkg:pypi/async-timeout",
		},
		{
			name:  "entry point string root brings its distribution's closure in",
			files: withClosureLock(map[string]string{"pyproject.toml": "[project]\nname = \"app\"\n\n[project.entry-points.\"flask.commands\"]\ntoolbar = \"debug_toolbar.cli:main\"\n"}),
			pkg:   "pkg:pypi/sqlparse@0.5.0",
		},
		{
			name:  "a settings string naming an unlocked distribution leaves its closure unknown",
			files: withLock(map[string]string{"app/settings.py": "MIDDLEWARE = [\"whitenoise.middleware.WhiteNoiseMiddleware\"]\n", "requirements-dev.txt": "whitenoise==6.6.0\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "complete pinned export of locked copies keeps the lockfile's markers",
			files: withLock(map[string]string{"requirements.txt": "requests==2.31.0 \\\n    --hash=sha256:00\nurllib3==2.2.1\nidna==3.7 ; python_version >= \"3.8\"\n"}),
			pkg:   "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black",
		},
		{
			name:  "unpinned requirements file cannot tell runtime from dev",
			files: withLock(map[string]string{"requirements.txt": "requests\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "requirements file pinning an unlocked version cannot tell runtime from dev",
			files: withLock(map[string]string{"requirements.txt": "requests==2.32.0\nurllib3==2.2.1\nidna==3.7\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "requirements file omitting a pinned name's dependency cannot tell runtime from dev",
			files: withLock(map[string]string{"requirements.txt": "requests==2.31.0\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "requirements file with a local path cannot tell runtime from dev",
			files: withLock(map[string]string{"requirements.txt": "./dist/app-0.1.0.tar.gz\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "requirements file including another cannot tell runtime from dev",
			files: withLock(map[string]string{"requirements.txt": "-r base.txt\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "requirements-docker.txt is a production install, not docs",
			files: withLock(map[string]string{"requirements-docker.txt": "black==24.4.2\npathspec==0.12.1\n"}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "stale poetry.lock beside the uv.lock in use feeds no markers",
			files: withLock(map[string]string{"poetry.lock": devPoetryLock}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name: "stale uv.lock beside the poetry.lock in use feeds no markers",
			files: map[string]string{
				"poetry.lock": devPoetryLock,
				"uv.lock":     "version = 1\n\n[manifest]\nmembers = [\"app\"]\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\ndependencies = [{ name = \"requests\" }]\n\n[package.dev-dependencies]\ndev = [{ name = \"black\" }]\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"black\"\nversion = \"24.4.2\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
				"app.py":      "import requests\n",
			},
			pkg: "pkg:pypi/black@24.4.2",
		},
		{
			name:  "a nested lockfile under the workspace lockfile feeds no markers",
			files: withLock(map[string]string{"packages/tool/poetry.lock": devPoetryLock}),
			pkg:   "pkg:pypi/black@24.4.2",
		},
		{
			name:  "a project manifest the lockfile's directory covers keeps the markers",
			files: withLock(map[string]string{"pyproject.toml": "[project]\nname = \"app\"\ndependencies = [\"requests\"]\n"}),
			pkg:   "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black",
		},
		{
			name: "a project manifest no lockfile covers cannot tell runtime from dev",
			files: map[string]string{
				"svc/uv.lock":         loadsetLock,
				"svc/app/__init__.py": "",
				"svc/app/main.py":     "import requests\n",
				"web/pyproject.toml":  "[project]\nname = \"web\"\ndependencies = [\"requests\"]\n",
				"web/web/__init__.py": "",
			},
			pkg: "pkg:pypi/black@24.4.2",
		},
		{
			name: "the same tree without the uncovered manifest refutes",
			files: map[string]string{
				"svc/uv.lock":         loadsetLock,
				"svc/app/__init__.py": "",
				"svc/app/main.py":     "import requests\n",
				"web/web/__init__.py": "",
			},
			pkg: "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := reachFor(t, tc.files, tc.pkg)
			if got := res.Refutation != nil; got != tc.refute {
				t.Fatalf("refuted = %v, want %v (refutation %+v; partiality %+v)", got, tc.refute, res.Refutation, res.Partiality)
			}
			if tc.refute {
				r := res.Refutation
				if r.Basis != plugin.RefutationPackageNotLoaded || r.Package != tc.purl {
					t.Fatalf("refutation = %+v, want basis %s package %s", r, plugin.RefutationPackageNotLoaded, tc.purl)
				}
				for _, want := range tc.detail {
					if !strings.Contains(r.Detail, want) {
						t.Errorf("detail %q lacks %q", r.Detail, want)
					}
				}
				if !strings.Contains(r.Detail, devAssumption) {
					t.Errorf("class (i) detail %q must state %q", r.Detail, devAssumption)
				}
				if strings.Contains(r.Detail, "\n") {
					t.Errorf("detail must be one line: %q", r.Detail)
				}
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonDynamicImportSpecifier); got != tc.reason {
				t.Errorf("dynamic_import reason = %v, want %v (%v)", got, tc.reason, res.Partiality.Reasons)
			}
			if tc.scoped != "" {
				s := scopedFor(res.Partiality, tc.scoped)
				if s == nil {
					t.Fatalf("no scoped reason for %s in %+v", tc.scoped, res.Partiality.Scoped)
				}
				if s.Reason != plugin.PartialReasonDynamicImportSpecifier || s.Targets == nil {
					t.Errorf("scoped reason %+v must be dynamic_import with bounded Targets", s)
				}
				if name, _, ok := pypiPackageRef(tc.pkg); ok && tc.noScope && containsString(s.Targets, pypiPURL(name)) {
					t.Errorf("scoped Targets %v must not include %s", s.Targets, name)
				}
			}
			if tc.fpOnly {
				for _, s := range res.Partiality.Scoped {
					if s.Package != "" || len(s.Targets) != 1 || s.Targets[0] != "" {
						t.Errorf("scoped reason %+v must target first-party code only", s)
					}
				}
			}
		})
	}
}

// TestLoadSet_ImportAbsenceNeverGrounds pins that package_not_loaded rests only on
// install-closure membership: a distribution in the runtime install is never refuted because
// no import reaches it, even when its module name shares nothing with its distribution name.
func TestLoadSet_ImportAbsenceNeverGrounds(t *testing.T) {
	lock := strings.Replace(loadsetLock, "    { name = \"django\" },\n]", "    { name = \"django\" },\n    { name = \"beautifulsoup4\" },\n]", 1) +
		"\n[[package]]\nname = \"beautifulsoup4\"\nversion = \"4.12.3\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
	files := withLock(nil)
	files["uv.lock"] = lock
	for _, purl := range []string{"pkg:pypi/beautifulsoup4@4.12.3", "pkg:pypi/click@8.1.7"} {
		if res := reachFor(t, files, purl); res.Refutation != nil {
			t.Errorf("%s is in the runtime install and no import reaches it: absence of an import must not refute it; got %+v", purl, res.Refutation)
		}
	}
	// The same lock still refutes a dev-only distribution, so the rows above are not vacuous.
	if res := reachFor(t, files, "pkg:pypi/pluggy@1.5.0"); res.Refutation == nil {
		t.Fatalf("a dev-only distribution must still refute in this fixture")
	}
}

// TestLoadSet_LoaderWithoutLockfile pins that with no lockfile an unbounded loader adds no
// scoped limit: the incomplete load set already refutes nothing, and an unbounded limit would
// pre-empt every row's own reason.
func TestLoadSet_LoaderWithoutLockfile(t *testing.T) {
	res := reachFor(t, map[string]string{"requirements.txt": "litellm==1.0.0\nblack==24.4.2\n", "app.py": "import litellm\n"}, "pkg:pypi/black@24.4.2")
	if len(res.Partiality.Scoped) != 0 || hasReason(res.Partiality, plugin.PartialReasonDynamicImportSpecifier) {
		t.Fatalf("a loader with no lockfile must add no dynamic_import limit; got %+v", res.Partiality)
	}
	if res.Refutation != nil {
		t.Fatalf("no lockfile must not refute; got %+v", res.Refutation)
	}
}

// dockerRun is the uv workspace plus a Dockerfile that runs cmd.
// k8sArgs is a Kubernetes deployment whose container command is the given vector.
func k8sArgs(vector string) string {
	return "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          image: app\n          command: [" + vector + "]\n"
}

// k8sPoetry is the docsPoetry project installed by a Kubernetes container command instead of
// a Dockerfile.
func k8sPoetry(vector string) map[string]string {
	f := docsPoetry(false, "true")
	delete(f, "Dockerfile")
	f["deploy/k8s/deployment.yaml"] = k8sArgs(vector)
	return f
}

// utf16Text encodes s as UTF-16, big- or little-endian, with or without a byte-order mark.
func utf16Text(s string, bigEndian, bom bool) string {
	var b bytes.Buffer
	if bom {
		s = "\ufeff" + s
	}
	for _, r := range s {
		if bigEndian {
			b.Write([]byte{byte(r >> 8), byte(r)})
		} else {
			b.Write([]byte{byte(r), byte(r >> 8)})
		}
	}
	return b.String()
}

func utf32le(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		b.Write([]byte{byte(r), byte(r >> 8), byte(r >> 16), byte(r >> 24)})
	}
	return b.String()
}

// zipText is a zip archive of files.
func zipText(files map[string]string) string {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			panic(err)
		}
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return b.String()
}

// appendFile returns files with extra appended to the named file.
func appendFile(files map[string]string, name, extra string) map[string]string {
	files[name] += extra
	return files
}

// pinnedDocker is the uv workspace with a requirements.txt pinning its runtime install, copied
// into an image whose RUN is cmd.
func pinnedDocker(cmd string) map[string]string {
	return withLock(map[string]string{"requirements.txt": pinnedRuntimeExport, "Dockerfile": "FROM python:3.12\nCOPY . .\nRUN " + cmd + "\n"})
}

// rewrittenReqs is the uv workspace with a requirements.txt pinning its runtime install and a
// requirements/docker.txt naming black, and the surface at name with content.
func rewrittenReqs(name, content string) map[string]string {
	return withLock(map[string]string{"requirements.txt": pinnedRuntimeExport, "requirements/docker.txt": "black==24.4.2\n", name: content})
}

// pipConfigCopy is pinnedDocker's tree with a pip configuration that adds black at src,
// copied to dest before the install.
func pipConfigCopy(src, dest string) map[string]string {
	return withLock(map[string]string{"requirements.txt": pinnedRuntimeExport, "requirements-dev.txt": "black==24.4.2\n",
		src:          "[install]\nrequirement = /src/requirements-dev.txt\n",
		"Dockerfile": "FROM python:3.12\nCOPY . /src\nCOPY " + src + " " + dest + "\nRUN pip install -r /src/requirements.txt\n"})
}

func dockerRun(cmd string) map[string]string {
	return withLock(map[string]string{"Dockerfile": "FROM python:3.12\nRUN " + cmd + "\n"})
}

const docsPoetryLock = devPoetryLock + "\n[[package]]\nname = \"mkdocs\"\nversion = \"1.5.0\"\ngroups = [\"docs\"]\n"

// docsPoetry is a poetry project with a main requests, a dev black and a docs mkdocs group
// (optional when docsOptional), installed by a Dockerfile that runs cmd.
func docsPoetry(docsOptional bool, cmd string) map[string]string {
	pyproject := "[tool.poetry]\nname = \"app\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"*\"\n\n" +
		"[tool.poetry.group.dev.dependencies]\nblack = \"*\"\n\n[tool.poetry.group.docs]\noptional = " + map[bool]string{true: "true", false: "false"}[docsOptional] +
		"\n\n[tool.poetry.group.docs.dependencies]\nmkdocs = \"*\"\n"
	return map[string]string{
		"app/__init__.py": "", "app/main.py": "import requests\n", "pyproject.toml": pyproject, "poetry.lock": docsPoetryLock,
		"Dockerfile": "FROM python:3.12\nRUN " + cmd + "\n",
	}
}

// docsUV is the uv workspace with a second dependency group, docs (mkdocs), a root pyproject
// whose [tool.uv] carries uvTable, and a Dockerfile that runs cmd.
func docsUV(uvTable, cmd string) map[string]string {
	lock := strings.Replace(loadsetLock, "[package.dev-dependencies]\ndev = [\n", "[package.dev-dependencies]\ndocs = [{ name = \"mkdocs\" }]\ndev = [\n", 1) +
		"\n[[package]]\nname = \"mkdocs\"\nversion = \"1.5.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
	f := withLock(map[string]string{
		"pyproject.toml": "[project]\nname = \"app\"\n\n[tool.uv]\n" + uvTable + "\n",
		"Dockerfile":     "FROM python:3.12\nRUN " + cmd + "\n",
	})
	f["uv.lock"] = lock
	return f
}

// pinnedRuntimeExport pins loadsetLock's runtime install exactly: a complete export.
const pinnedRuntimeExport = "requests==2.31.0\nurllib3==2.2.1\nidna==3.7\nsqlalchemy==2.0.30\nlitellm==1.40.0\nclick==8.1.7\ndjango==5.0.6\n"

// pdmOptLock locks requests in pdm's default group and pysocks only in an optional socks group.
const pdmOptLock = "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\ngroups = [\"default\"]\n\n[[package]]\nname = \"pysocks\"\nversion = \"1.7.1\"\ngroups = [\"socks\"]\n"

const devPDMLock = "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\ngroups = [\"default\"]\n\n[[package]]\nname = \"black\"\nversion = \"24.4.2\"\ngroups = [\"lint\"]\n"

// scanFor runs the install scan alone over files and returns the load set it filled.
func scanFor(t *testing.T, files map[string]string) *loadSet {
	t.Helper()
	dir := writeTree(t, files)
	ls := &loadSet{complete: true, reqRuntime: map[string]bool{}, installed: map[string]bool{}, projectNames: map[string]bool{}}
	ls.locks = loadLocks(dir, ls)
	ls.scanInstalls(dir)
	return ls
}

// TestLoadSet_InstallCommands pins the install-command scan: a production install that keeps
// a lockfile group blocks that group's distributions; an install command naming a
// distribution blocks it; anything the scan cannot positively parse blocks every refutation.
// veto is a substring of the markerless reason the scan must record ("" for none).
func TestLoadSet_InstallCommands(t *testing.T) {
	cases := []struct {
		name   string
		files  map[string]string
		pkg    string
		refute bool
		veto   string
		detail []string
		clean  bool // no veto: an unrefuted row is blocked by what the scan models, not by a veto
	}{
		// Group-precise keeps (B2).
		{name: "poetry --without dev still installs the non-optional docs group", files: docsPoetry(false, "poetry install --without dev --no-root"), pkg: "pkg:pypi/mkdocs@1.5.0"},
		{name: "poetry --no-dev still installs the non-optional docs group", files: docsPoetry(false, "poetry install --no-dev"), pkg: "pkg:pypi/mkdocs@1.5.0"},
		{name: "poetry --without dev,docs installs neither", files: docsPoetry(false, "poetry install --without dev,docs"), pkg: "pkg:pypi/mkdocs@1.5.0", refute: true},
		{name: "poetry --without dev leaves an optional docs group out", files: docsPoetry(true, "poetry install --without dev"), pkg: "pkg:pypi/mkdocs@1.5.0", refute: true},
		{name: "poetry --with an optional group installs it", files: docsPoetry(true, "poetry install --without dev --with docs"), pkg: "pkg:pypi/mkdocs@1.5.0"},
		{name: "poetry --without dev does not keep dev", files: docsPoetry(false, "poetry install --without dev"), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "uv --no-dev keeps default-groups = all", files: docsUV(`default-groups = "all"`, "uv sync --frozen --no-dev"), pkg: "pkg:pypi/mkdocs@1.5.0"},
		{name: "uv --no-dev keeps a listed default group", files: docsUV(`default-groups = ["dev", "docs"]`, "uv sync --no-dev"), pkg: "pkg:pypi/mkdocs@1.5.0"},
		{name: "uv --no-group drops a listed default group", files: docsUV(`default-groups = ["dev", "docs"]`, "uv sync --no-dev --no-group docs"), pkg: "pkg:pypi/mkdocs@1.5.0", refute: true},
		{name: "uv sync without default-groups keeps only dev", files: docsUV(`package = true`, "uv sync"), pkg: "pkg:pypi/mkdocs@1.5.0", refute: true},
		{name: "uv --all-extras keeps an extra", files: dockerRun("uv sync --no-dev --all-extras"), pkg: "pkg:pypi/asyncpg@0.29.0"},
		{name: "uv --no-dev leaves an unrequested extra out", files: dockerRun("uv sync --no-dev"), pkg: "pkg:pypi/asyncpg@0.29.0", refute: true},
		{name: "pdm --prod drops non-default groups", files: map[string]string{"pdm.lock": devPDMLock, "app.py": "import requests\n", "Dockerfile": "RUN pdm install --prod\n"}, pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "pdm --prod -G keeps the named group", files: map[string]string{"pdm.lock": devPDMLock, "app.py": "import requests\n", "Dockerfile": "RUN pdm install --prod -G lint\n"}, pkg: "pkg:pypi/black@24.4.2"},
		{name: "pdm install without --prod keeps every group", files: map[string]string{"pdm.lock": devPDMLock, "app.py": "import requests\n", "Dockerfile": "RUN pdm install\n"}, pkg: "pkg:pypi/black@24.4.2"},

		// Deploy surfaces (B1, S1).
		{name: "compose command uv run syncs dev", files: withLock(map[string]string{"docker-compose.yml": "services:\n  web:\n    build: .\n    command: uv run python -m app.main\n"}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "compose command uv run --no-dev does not", files: withLock(map[string]string{"docker-compose.yml": "services:\n  web:\n    command: uv run --no-dev python -m app.main\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true,
			detail: []string{"install commands checked in 1 file (docker-compose.yml)"}},
		{name: "CD workflow running a Lambda deploy command is production", files: withLock(map[string]string{".github/workflows/cd.yml": "name: CD\non: push\njobs:\n  ship:\n    runs-on: ubuntu-latest\n    steps:\n      - run: uv sync\n      - run: zip -r app.zip .venv app && aws lambda update-function-code --function-name x --zip-file fileb://app.zip\n"}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "a Lambda deploy command makes a generically named job production", files: withLock(map[string]string{".github/workflows/main.yml": "name: Main\non: push\njobs:\n  ship:\n    runs-on: ubuntu-latest\n    steps:\n      - run: uv sync\n      - run: aws lambda update-function-code --function-name x --zip-file fileb://app.zip\n"}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "a generically named job with no deploy signal is not production", files: withLock(map[string]string{".github/workflows/main.yml": "name: Main\non: push\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: uv sync\n      - run: uv run ruff check .\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "GitLab deploy job is production", files: withLock(map[string]string{".gitlab-ci.yml": "deploy:\n  script:\n    - uv sync\n    - ./ship.sh\n"}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "GitLab test job is not production", files: withLock(map[string]string{".gitlab-ci.yml": "stages: [test]\nunit:\n  stage: test\n  script:\n    - uv sync\n    - uv run pytest\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "GitLab include is not read", files: withLock(map[string]string{".gitlab-ci.yml": "include:\n  - project: ops/ci\n    file: python.yml\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "include"},
		{name: "unparsed compose file", files: withLock(map[string]string{"docker-compose.yml": "services: [\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "docker-compose.yml: could not be parsed"},
		{name: "unparsed fly.toml", files: withLock(map[string]string{"fly.toml": "[build\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "fly.toml: could not be parsed"},
		{name: "unparsed workflow", files: withLock(map[string]string{".github/workflows/ci.yml": "jobs: [\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "ci.yml: could not be parsed"},
		{name: "composite action is production", files: withLock(map[string]string{".github/actions/setup/action.yml": "runs:\n  using: composite\n  steps:\n    - run: uv sync\n      shell: bash\n"}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "no install surface: detail says so", files: withLock(nil), pkg: "pkg:pypi/black@24.4.2", refute: true, detail: []string{"no file in the repository runs an install command"}},

		// Named distributions: blocked with their lockfile closure, in any job.
		{name: "pip install names black", files: dockerRun("pip install black==24.4.2 pathspec==0.12.1"), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "pip install of black leaves pytest refutable", files: dockerRun("pip install black==24.4.2 pathspec==0.12.1"), pkg: "pkg:pypi/pytest@8.2.0", refute: true},
		{name: "pip install of black blocks its closure", files: dockerRun("pip install black==24.4.2 pathspec==0.12.1"), pkg: "pkg:pypi/pathspec@0.12.1", clean: true},
		{name: "pip install -r reads the file", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nCOPY deploy/ deploy/\nRUN pip install -r deploy/base.txt\n", "deploy/base.txt": "black==24.4.2\npathspec==0.12.1\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "pip install -r leaves unnamed pytest refutable", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nCOPY deploy/ deploy/\nRUN pip install -r deploy/base.txt\n", "deploy/base.txt": "black==24.4.2\npathspec==0.12.1\n"}), pkg: "pkg:pypi/pytest@8.2.0", refute: true},
		{name: "a test CI job's install still names black", files: withLock(map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    environment: test\n    steps:\n      - run: pip install black==24.4.2 pathspec==0.12.1\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},

		// Installs outside the lockfile install an unlisted transitive closure: every refutation blocked.
		{name: "unpinned pip install blocks all", files: dockerRun("pip install black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "black is not pinned"},
		{name: "unpinned pip3 install blocks all", files: dockerRun("pip3 install --no-cache-dir Black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "black is not pinned"},
		{name: "unpinned python -m pip install blocks all", files: dockerRun("python3.12 -m pip install -U black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "black is not pinned"},
		{name: "unpinned uv pip install blocks all", files: dockerRun("uv pip install --system black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "black is not pinned"},
		{name: "a pin without its locked closure blocks all", files: dockerRun("pip install black==24.4.2"), pkg: "pkg:pypi/pytest@8.2.0", veto: "pathspec, in the locked closure"},
		{name: "pipx install blocks all", files: dockerRun("pipx install black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "pipx install installs black"},
		{name: "pipx run blocks all", files: withLock(map[string]string{"Makefile": "lint:\n\tpipx run ruff check .\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "pipx run installs ruff"},
		{name: "uvx blocks all", files: dockerRun("uvx black --check ."), pkg: "pkg:pypi/pytest@8.2.0", veto: "uvx installs black"},
		{name: "uv tool install blocks all", files: dockerRun("uv tool install ruff"), pkg: "pkg:pypi/pytest@8.2.0", veto: "uv tool install installs ruff"},
		{name: "uv run --with blocks all", files: dockerRun("uv run --no-dev --with rich python -m app"), pkg: "pkg:pypi/pytest@8.2.0", veto: "--with"},
		{name: "pip install of extras blocks all", files: dockerRun("pip install black[d]==24.4.2 pathspec==0.12.1"), pkg: "pkg:pypi/pytest@8.2.0", veto: "extras"},
		{name: "pip install of bootstrap tools is not a veto", files: dockerRun("pip install -U pip setuptools wheel"), pkg: "pkg:pypi/black@24.4.2", refute: true},

		// Families the scan does not parse, and forms it cannot read: every refutation blocked.
		{name: "uv add", files: dockerRun("uv add black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "uv add"},
		{name: "poetry add", files: dockerRun("poetry add black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "poetry add"},
		{name: "pdm add", files: dockerRun("pdm add black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "pdm add"},
		{name: "pipenv install with packages", files: dockerRun("pipenv install black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "pipenv install with packages"},
		{name: "conda install", files: dockerRun("conda install -y numpy"), pkg: "pkg:pypi/pytest@8.2.0", veto: "conda install"},
		{name: "mamba install", files: dockerRun("mamba install numpy"), pkg: "pkg:pypi/pytest@8.2.0", veto: "mamba install"},
		{name: "micromamba create", files: dockerRun("micromamba create -f env.yml"), pkg: "pkg:pypi/pytest@8.2.0", veto: "micromamba create"},
		{name: "easy_install", files: dockerRun("easy_install black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "easy_install"},
		{name: "setup.py install", files: dockerRun("python setup.py install"), pkg: "pkg:pypi/pytest@8.2.0", veto: "setup.py install"},
		{name: "pipx install-all", files: dockerRun("pipx install-all pipx.json"), pkg: "pkg:pypi/pytest@8.2.0", veto: "install-all"},
		{name: "unknown pip subcommand", files: dockerRun("pip frobnicate"), pkg: "pkg:pypi/pytest@8.2.0", veto: "pip frobnicate"},
		{name: "unknown pip install option", files: dockerRun("pip install --group dev"), pkg: "pkg:pypi/pytest@8.2.0", veto: "--group"},
		{name: "variable in pip install arguments", files: dockerRun("pip install $PKGS"), pkg: "pkg:pypi/pytest@8.2.0", veto: "variable or substitution"},
		{name: "variable in a pip install option value", files: dockerRun("pip install --index-url $INDEX black==24.4.2"), pkg: "pkg:pypi/pytest@8.2.0", veto: "variable or substitution"},
		{name: "substitution in pip install arguments", files: dockerRun("pip install $(cat deps.txt)"), pkg: "pkg:pypi/pytest@8.2.0", veto: "variable or substitution"},
		{name: "variable names the installer", files: dockerRun("$PIP install black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "variable or substitution"},
		{name: "pip install of the project", files: dockerRun("pip install ."), pkg: "pkg:pypi/pytest@8.2.0", veto: "project, path"},
		{name: "pip install -e of the project", files: dockerRun("pip install -e ."), pkg: "pkg:pypi/pytest@8.2.0", veto: "-e"},
		{name: "pip install of a wheel", files: dockerRun("pip install dist/app-1.0-py3-none-any.whl"), pkg: "pkg:pypi/pytest@8.2.0", veto: "project, path"},
		{name: "pip install of a URL", files: dockerRun("pip install https://example.com/app-1.0.tar.gz"), pkg: "pkg:pypi/pytest@8.2.0", veto: "project, path"},
		{name: "pip install of a VCS reference", files: dockerRun("pip install git+https://github.com/example/app"), pkg: "pkg:pypi/pytest@8.2.0", veto: "project, path"},
		{name: "pip install of a name the lockfile does not lock", files: dockerRun("pip install flask"), pkg: "pkg:pypi/pytest@8.2.0", veto: "flask is not pinned"},
		{name: "pip install -r from a URL", files: dockerRun("pip install -r https://example.com/requirements.txt"), pkg: "pkg:pypi/pytest@8.2.0", veto: "is a URL"},
		{name: "pip install -r of a file not copied into the image", files: dockerRun("pip install -r requirements-prod.txt"), pkg: "pkg:pypi/pytest@8.2.0", veto: "not copied into the image"},
		{name: "pip install -r of a missing file", files: withLock(map[string]string{"deploy.sh": "pip install -r requirements-prod.txt\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "not in the repository"},
		{name: "pip install -r of a file outside the repository", files: withLock(map[string]string{"deploy.sh": "pip install -r ../shared/requirements.txt\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "not in the repository"},
		{name: "pip install -r after a cd the scan cannot follow", files: withLock(map[string]string{"deploy.sh": "cd \"$APP\"\npip install -r requirements.txt\n", "requirements.txt": pinnedRuntimeExport}), pkg: "pkg:pypi/pytest@8.2.0", veto: "change of directory"},
		{name: "pip install -r follows a literal cd", files: withLock(map[string]string{"deploy.sh": "cd deploy\npip install -r base.txt\n", "deploy/base.txt": "black==24.4.2\npathspec==0.12.1\n", "base.txt": pinnedRuntimeExport}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "pip install -r of a file with an editable line", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nCOPY deploy/ deploy/\nRUN pip install -r deploy/base.txt\n", "deploy/base.txt": "-e ./lib\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "deploy/base.txt"},
		{name: "pip install --no-deps alongside another pip install", files: dockerRun("pip install --no-deps black==24.4.2 && pip install requests==2.31.0"), pkg: "pkg:pypi/pytest@8.2.0", veto: "--no-deps"},
		{name: "a lockfile install with no lockfile of its format", files: dockerRun("poetry install --only main"), pkg: "pkg:pypi/pytest@8.2.0", veto: "no poetry lockfile"},

		// Every file is walked; only a committed node_modules or site-packages is skipped.
		{name: "a Dockerfile under build/ is read", files: withLock(map[string]string{"build/docker/Dockerfile": "FROM python:3.12\nRUN uv sync --frozen\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "a Dockerfile under a dot-directory is read", files: withLock(map[string]string{".docker/Dockerfile": "FROM python:3.12\nRUN uv sync --frozen\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "an Elastic Beanstalk hook under .platform is read", files: withLock(map[string]string{".platform/hooks/prebuild/01_deps.sh": "#!/bin/bash\npip install black==24.4.2 pathspec==0.12.1\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "a Dockerfile inside a committed node_modules is not read", files: withLock(map[string]string{"node_modules/tool/Dockerfile": "FROM python:3.12\nRUN uv sync --frozen\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},

		// Any file carrying an installer token is a candidate surface, whatever its name.
		{name: "an extensionless entrypoint script is read", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nRUN uv sync --frozen --no-dev\nCOPY docker-entrypoint /docker-entrypoint\nENTRYPOINT [\"/docker-entrypoint\"]\n", "docker-entrypoint": "#!/bin/sh\npip install black==24.4.2 pathspec==0.12.1\nexec uv run --no-sync app\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "Heroku bin/post_compile is read", files: withLock(map[string]string{"bin/post_compile": "#!/usr/bin/env bash\npip install black==24.4.2 pathspec==0.12.1\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "a k8s container command is read", files: withLock(map[string]string{"deploy/k8s/deployment.yaml": "kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          command: [\"sh\", \"-c\", \"pip install black==24.4.2 pathspec==0.12.1 && gunicorn app:app\"]\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "an AWS CodeBuild buildspec is read", files: withLock(map[string]string{"buildspec.yml": "version: 0.2\nphases:\n  install:\n    commands:\n      - uv sync --frozen\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "an installer token the scan does not parse vetoes", files: withLock(map[string]string{"docs/setup.md": "Run `uv sync` first.\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "an install command the scanner does not parse"},

		// Install families the scan does not model.
		{name: "pex", files: dockerRun("pex -r requirements-dev.txt -o app.pex"), pkg: "pkg:pypi/pytest@8.2.0", veto: "pex"},
		{name: "shiv", files: dockerRun("shiv -o app.pyz ."), pkg: "pkg:pypi/pytest@8.2.0", veto: "shiv"},
		{name: "flit install", files: dockerRun("flit install --deps all"), pkg: "pkg:pypi/pytest@8.2.0", veto: "flit install"},
		{name: "rye sync", files: dockerRun("rye sync"), pkg: "pkg:pypi/pytest@8.2.0", veto: "rye sync"},
		{name: "hatch env create", files: dockerRun("hatch env create"), pkg: "pkg:pypi/pytest@8.2.0", veto: "hatch env"},
		{name: "pixi install", files: dockerRun("pixi install"), pkg: "pkg:pypi/pytest@8.2.0", veto: "pixi install"},
		{name: "micropipenv install", files: dockerRun("micropipenv install --dev"), pkg: "pkg:pypi/pytest@8.2.0", veto: "micropipenv"},
		{name: "a system package of a Python distribution", files: dockerRun("apt-get install -y python3-black"), pkg: "pkg:pypi/pytest@8.2.0", veto: "python3-black"},
		{name: "system interpreter packages are not a veto", files: dockerRun("apt-get install -y python3-pip python3-venv python3-dev"), pkg: "pkg:pypi/pytest@8.2.0", refute: true},

		// pip configuration.
		{name: "ENV PIP_REQUIREMENT", files: withLock(map[string]string{"requirements.txt": pinnedRuntimeExport, "requirements-dev.txt": "black==24.4.2\npathspec==0.12.1\n", "Dockerfile": "FROM python:3.12\nENV PIP_REQUIREMENT=requirements-dev.txt\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "PIP_REQUIREMENT"},
		{name: "a committed pip.conf", files: withLock(map[string]string{"requirements.txt": pinnedRuntimeExport, "requirements-dev.txt": "black==24.4.2\npathspec==0.12.1\n", "pip.conf": "[install]\nrequirement = requirements-dev.txt\n", "Dockerfile": "FROM python:3.12\nCOPY pip.conf /etc/pip.conf\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pip configuration file"},

		// Global options between the family word and the subcommand, in a file that is a
		// candidate only by content.
		{name: "k8s args: pip --no-cache-dir install", files: withLock(map[string]string{"deploy/k8s/deployment.yaml": k8sArgs(`"pip", "--no-cache-dir", "install", "black==24.4.2"`)}), pkg: "pkg:pypi/pytest@8.2.0", veto: "pathspec, in the locked closure"},
		{name: "k8s command: python -m pip -q install", files: withLock(map[string]string{"deploy/k8s/deployment.yaml": k8sArgs(`"sh", "-c", "python -m pip -q install black==24.4.2"`)}), pkg: "pkg:pypi/pytest@8.2.0", veto: "pathspec, in the locked closure"},
		{name: "k8s command: uv --no-cache sync --frozen", files: withLock(map[string]string{"deploy/k8s/deployment.yaml": k8sArgs(`"sh", "-c", "uv --no-cache sync --frozen"`)}), pkg: "pkg:pypi/pytest@8.2.0"},
		{name: "k8s command: poetry -C . install", files: k8sPoetry(`"sh", "-c", "poetry -C . install"`), pkg: "pkg:pypi/mkdocs@1.5.0"},
		{name: "k8s command: poetry --no-interaction install", files: k8sPoetry(`"sh", "-c", "poetry --no-interaction install"`), pkg: "pkg:pypi/mkdocs@1.5.0"},
		{name: "k8s command: pipenv --python 3.12 install --dev", files: withLock(map[string]string{"deploy/k8s/deployment.yaml": k8sArgs(`"sh", "-c", "pipenv --python 3.12 install --dev"`)}), pkg: "pkg:pypi/pytest@8.2.0"},
		{name: "k8s command: a variable before install", files: withLock(map[string]string{"deploy/k8s/deployment.yaml": k8sArgs(`"sh", "-c", "pip $EXTRA install black==24.4.2"`)}), pkg: "pkg:pypi/pytest@8.2.0"},

		// A Dockerfile by content, whatever its name; Dockerfile instructions in a file read
		// otherwise veto.
		{name: "a Dockerfile named by content: its COPY is followed", files: withLock(map[string]string{"docker/web.prod": "FROM python:3.12\nWORKDIR /app\nCOPY requirements/docker.txt requirements.txt\nRUN pip install -r requirements.txt\n", "requirements.txt": pinnedRuntimeExport, "requirements/docker.txt": "black==24.4.2\npathspec==0.12.1\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "a Dockerfile named by content after a syntax directive and ARG", files: withLock(map[string]string{"build/app.image": "# syntax=docker/dockerfile:1\nARG PY=3.12\nFROM python:${PY}\nCOPY requirements/docker.txt requirements.txt\nRUN pip install -r requirements.txt\n", "requirements.txt": pinnedRuntimeExport, "requirements/docker.txt": "black==24.4.2\npathspec==0.12.1\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "a Dockerfile named by content that installs the runtime export refutes", files: withLock(map[string]string{"docker/web.prod": "FROM python:3.12\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\n", "requirements.txt": pinnedRuntimeExport}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "Dockerfile instructions in docs", files: withLock(map[string]string{"docs/deploy.md": "Build with:\n\n```dockerfile\n" + strings.TrimSuffix("FROM python:3.12\nWORKDIR /app\nCOPY requirements/docker.txt requirements.txt\nRUN pip install -r requirements.txt\n", "\n") + "\n```\n", "requirements.txt": pinnedRuntimeExport, "requirements/docker.txt": "black==24.4.2\npathspec==0.12.1\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "Dockerfile instructions in a file not read as a Dockerfile"},
		{name: "a partial Dockerfile snippet in docs", files: withLock(map[string]string{"docs/deploy.md": "Add to your image:\n\n    COPY requirements/docker.txt requirements.txt\n    RUN pip install -r requirements.txt\n", "requirements.txt": pinnedRuntimeExport, "requirements/docker.txt": "black==24.4.2\npathspec==0.12.1\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "Dockerfile instructions in a file not read as a Dockerfile"},
		{name: "lowercase Dockerfile instructions in a heredoc", files: withLock(map[string]string{"deploy/build.sh": "cat > Dockerfile <<EOF\nfrom python:3.12\ncopy requirements/docker.txt requirements.txt\nrun pip install -r requirements.txt\nEOF\n", "requirements.txt": pinnedRuntimeExport, "requirements/docker.txt": "black==24.4.2\npathspec==0.12.1\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "Dockerfile instructions in a file not read as a Dockerfile"},
		{name: "control: prose that starts a line with Add or From is not an instruction", files: withLock(map[string]string{"README.md": "Add the runtime requirements:\n\n    pip install -r requirements.txt\n\nFrom then on the app runs.\n", "requirements.txt": pinnedRuntimeExport}), pkg: "pkg:pypi/black@24.4.2", refute: true},

		// A conda environment file installs packages and a pip section without naming them in a
		// command.
		{name: "conda environment.yml with a pip section", files: withLock(map[string]string{"environment.yml": "name: app\ndependencies:\n  - python=3.12\n  - pip\n  - pip:\n      - black==24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "conda environment file"},
		{name: "a conda file by its channels", files: withLock(map[string]string{"ci/py.yml": "channels:\n  - conda-forge\ndependencies:\n  - python=3.12\n  - black=24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "conda environment file"},
		{name: "a conda file by its pip section alone", files: withLock(map[string]string{"deploy/conda.yaml": "dependencies:\n  - python=3.12\n  - pip:\n      - black==24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "conda environment file"},
		{name: "environment.yaml by its name alone", files: withLock(map[string]string{"environment.yaml": "dependencies:\n  - python=3.12\n  - black=24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "conda environment file"},
		{name: "binder/environment.yml", files: withLock(map[string]string{"binder/environment.yml": "dependencies:\n  - python=3.12\n  - black=24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "conda environment file"},
		{name: "control: a channels list without dependencies is not a conda file", files: withLock(map[string]string{"deploy/notify.yml": "channels:\n  - builds\n  - releases\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "control: a Helm chart's dependencies are not a conda file", files: withLock(map[string]string{"deploy/chart/Chart.yaml": "apiVersion: v2\nname: app\nversion: 0.1.0\ndependencies:\n  - name: redis\n    version: 18.0.0\n    repository: https://charts.bitnami.com/bitnami\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},

		// Other environment managers install what their manifest or lock file lists the same way.
		{name: "pixi.toml with PyPI dependencies", files: withLock(map[string]string{"pixi.toml": "[workspace]\nchannels = [\"conda-forge\"]\nplatforms = [\"linux-64\"]\n\n[dependencies]\npython = \"3.12.*\"\n\n[pypi-dependencies]\nblack = \"==24.4.2\"\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pixi manifest"},
		{name: "pixi.toml by its name alone", files: withLock(map[string]string{"pixi.toml": "[workspace]\nchannels = [\"conda-forge\"]\n\n[dependencies]\nblack = \"24.4.2.*\"\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pixi manifest"},
		{name: "pyproject.toml with [tool.pixi]", files: withLock(map[string]string{"pyproject.toml": "[project]\nname = \"app\"\n\n[tool.pixi.workspace]\nchannels = [\"conda-forge\"]\nplatforms = [\"linux-64\"]\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pixi manifest"},
		{name: "a pixi feature's PyPI dependencies", files: withLock(map[string]string{"envs/prod.toml": "[feature.prod.pypi-dependencies]\nblack = \"==24.4.2\"\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pixi manifest"},
		{name: "top-level PyPI dependencies in any TOML file", files: withLock(map[string]string{"envs/web.toml": "[pypi-dependencies]\nblack = \"==24.4.2\"\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pixi manifest"},
		{name: "control: a pyproject.toml without [tool.pixi]", files: withLock(map[string]string{"pyproject.toml": "[project]\nname = \"app\"\n\n[tool.black]\nline-length = 100\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "pixi.lock by its name", files: withLock(map[string]string{"pixi.lock": "version: 6\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pixi lock file"},
		{name: "a pixi lock file by its content", files: withLock(map[string]string{"envs/prod.lock": "version: 6\nenvironments:\n  default:\n    channels:\n    - url: https://conda.anaconda.org/conda-forge/\npackages:\n- pypi: https://files.pythonhosted.org/packages/black-24.4.2-py3-none-any.whl\n  name: black\n  version: 24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pixi lock file"},
		{name: "control: environments without packages is not a pixi lock", files: withLock(map[string]string{"deploy/targets.yml": "environments:\n  prod:\n    url: https://app.example.com\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "control: packages without environments is not a pixi lock", files: withLock(map[string]string{"deploy/monorepo.yml": "packages:\n- api\n- web\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "conda-lock.yml by its name", files: withLock(map[string]string{"conda-lock.yml": "version: 1\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "conda lock file"},
		{name: "a conda lock file by its content", files: withLock(map[string]string{"deploy/env.lock.yml": "version: 1\nmetadata:\n  channels:\n  - url: conda-forge\n  platforms:\n  - linux-64\npackage:\n- name: black\n  version: 24.4.2\n  manager: pip\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "conda lock file"},
		{name: "control: a Kubernetes manifest's metadata is not a conda lock", files: withLock(map[string]string{"deploy/k8s/service.yaml": "apiVersion: v1\nkind: Service\nmetadata:\n  name: app\nspec:\n  ports:\n  - port: 80\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "control: a package list without metadata is not a conda lock", files: withLock(map[string]string{"deploy/release.yml": "package:\n- api\n- web\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "a conda explicit spec", files: withLock(map[string]string{"deploy/conda-linux-64.lock": "# platform: linux-64\n@EXPLICIT\nhttps://conda.anaconda.org/conda-forge/noarch/black-24.4.2-pyhd8ed1ab_0.conda\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "conda explicit spec"},
		{name: "spack.yaml by its name", files: withLock(map[string]string{"spack.yaml": "specs: []\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "spack environment"},
		{name: "spack.lock by its name", files: withLock(map[string]string{"spack.lock": "{}\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "spack environment"},
		{name: "a spack environment by its content", files: withLock(map[string]string{"envs/prod/env.yaml": "spack:\n  specs:\n  - py-black@24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "spack environment"},
		{name: "a spack lock by its content", files: withLock(map[string]string{"envs/prod/env.json": "{\"_meta\": {\"lockfile-version\": 5}, \"roots\": [], \"concrete_specs\": {}}\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "spack environment"},
		{name: "devbox.json", files: withLock(map[string]string{"devbox.json": "{\"packages\": [\"python312Packages.black@24.4.2\"]}\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "devbox environment"},
		{name: "devbox.lock", files: withLock(map[string]string{"devbox.lock": "{\"lockfile_version\": \"1\"}\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "devbox environment"},
		{name: "a Nix flake with Python packages", files: withLock(map[string]string{"flake.nix": "{ outputs = { nixpkgs, ... }: { devShells.default = pkgs.mkShell { packages = [ (pkgs.python312.withPackages (ps: [ ps.black ])) ]; }; }; }\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "Nix expression with Python packages"},
		{name: "a Nix flake built with uv2nix", files: withLock(map[string]string{"flake.nix": "{ outputs = { uv2nix, ... }: { ws = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; }; }; }\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "Nix expression with Python packages"},
		{name: "a Nix shell built with mach-nix", files: withLock(map[string]string{"shell.nix": "let m = import (builtins.fetchGit { url = \"https://github.com/DavHau/mach-nix\"; }) {}; in m.mkShell { requirements = \"black\"; }\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "Nix expression with Python packages"},
		{name: "a Nix expression naming Python in capitals", files: withLock(map[string]string{"nix/env.nix": "{ pkgs }: pkgs.mkShell { name = \"Python-tools\"; }\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "Nix expression with Python packages"},
		{name: "control: a Nix flake without Python packages", files: withLock(map[string]string{"flake.nix": "{ outputs = { nixpkgs, ... }: { devShells.default = pkgs.mkShell { packages = [ pkgs.go ]; }; }; }\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "control: Python packages named outside a Nix file", files: withLock(map[string]string{"docs/nix.md": "Use python312Packages.black in your shell.\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},

		// Files the scan cannot read as text: text in any Unicode encoding is decoded and
		// read; an archive or executable can bundle distributions and blocks every refutation.
		{name: "a UTF-8 script with a BOM is read from its first byte", files: withLock(map[string]string{"deploy.ps1": "\xef\xbb\xbfpip install black\r\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "black is not pinned"},
		{name: "a UTF-16LE PowerShell script with a BOM is read", files: withLock(map[string]string{"deploy.ps1": utf16Text("pip install black\r\n", false, true)}), pkg: "pkg:pypi/pytest@8.2.0", veto: "black is not pinned"},
		{name: "a UTF-16BE script with a BOM is read", files: withLock(map[string]string{"deploy.ps1": utf16Text("pip install black\r\n", true, true)}), pkg: "pkg:pypi/pytest@8.2.0", veto: "black is not pinned"},
		{name: "a UTF-16LE script without a BOM is read", files: withLock(map[string]string{"deploy.ps1": utf16Text("pip install black\r\n", false, false)}), pkg: "pkg:pypi/pytest@8.2.0", veto: "black is not pinned"},
		{name: "a UTF-32LE script with a BOM is read", files: withLock(map[string]string{"deploy.ps1": "\xff\xfe\x00\x00" + utf32le("pip install black\n")}), pkg: "pkg:pypi/pytest@8.2.0", veto: "black is not pinned"},
		{name: "a committed Lambda layer zip", files: withLock(map[string]string{"layer.zip": zipText(map[string]string{"python/black/__init__.py": "", "python/black-24.4.2.dist-info/METADATA": "Name: black\n"})}), pkg: "pkg:pypi/black@24.4.2", veto: "layer.zip: archive"},
		{name: "a committed pex: a shebang before a zip", files: withLock(map[string]string{"dist/app": "#!/usr/bin/env python3\n" + zipText(map[string]string{"black/__init__.py": ""})}), pkg: "pkg:pypi/black@24.4.2", veto: "dist/app: archive"},
		{name: "a committed sdist tarball", files: withLock(map[string]string{"vendor/black-24.4.2": "\x1f\x8b\x08\x00\x00\x00\x00\x00"}), pkg: "pkg:pypi/black@24.4.2", veto: "vendor/black-24.4.2: archive"},
		{name: "a committed tar without a suffix", files: withLock(map[string]string{"vendor/bundle": strings.Repeat("\x00", 257) + "ustar\x0000" + strings.Repeat("\x00", 100)}), pkg: "pkg:pypi/black@24.4.2", veto: "vendor/bundle: archive"},
		{name: "an archive suffix alone vetoes", files: withLock(map[string]string{"vendor/deps.tar.gz": "not really gzip"}), pkg: "pkg:pypi/black@24.4.2", veto: "vendor/deps.tar.gz: archive"},
		{name: "a committed executable", files: withLock(map[string]string{"bin/app": "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00", 64)}), pkg: "pkg:pypi/black@24.4.2", veto: "bin/app: executable"},
		{name: "an image is neither text nor an archive", files: withLock(map[string]string{"docs/logo.png": "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + strings.Repeat("\x00", 32)}), pkg: "pkg:pypi/black@24.4.2", refute: true},

		// Index and find-links locations: a remote https index is a fetch option; anything else
		// (a directory, file: URL, relative, loopback or unresolvable value) is an install
		// source the lockfile does not describe, and blocks every refutation.
		{name: "pip install --find-links into the repository", files: dockerRun("pip install -U --find-links ./wheels pip setuptools wheel"), pkg: "pkg:pypi/pytest@8.2.0", veto: `--find-links "./wheels" is not a remote https index`},
		{name: "pip install -f with a directory", files: dockerRun("pip install -U -f vendor/ pip"), pkg: "pkg:pypi/pytest@8.2.0", veto: `-f "vendor/" is not a remote https index`},
		{name: "pip install --find-links=file: URL", files: dockerRun("pip install -U --find-links=file:///app/wheels pip"), pkg: "pkg:pypi/pytest@8.2.0", veto: `--find-links "file:///app/wheels"`},
		{name: "pip install --extra-index-url on loopback", files: dockerRun("pip install -U --extra-index-url https://127.0.0.1:8080/simple pip"), pkg: "pkg:pypi/pytest@8.2.0", veto: `--extra-index-url "https://127.0.0.1:8080/simple"`},
		{name: "pip install --index-url over plain http", files: dockerRun("pip install -U -i http://mirror.example.com/simple pip"), pkg: "pkg:pypi/pytest@8.2.0", veto: `-i "http://mirror.example.com/simple"`},
		{name: "a remote https index and find-links stay fetch options", files: dockerRun("pip install -U --index-url https://mirror.example.com/simple --extra-index-url=https://pypi.org/simple -f https://wheels.example.com/ pip setuptools wheel"), pkg: "pkg:pypi/pytest@8.2.0", refute: true},
		{name: "--find-links in a requirements file", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nCOPY deploy/ deploy/\nRUN pip install -r deploy/base.txt\n", "deploy/base.txt": "--find-links ./wheels\nblack==24.4.2\npathspec==0.12.1\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: `--find-links "./wheels"`},
		{name: "a remote --index-url in a requirements file stays a fetch option", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nCOPY deploy/ deploy/\nRUN pip install -r deploy/base.txt\n", "deploy/base.txt": "--index-url https://mirror.example.com/simple\nblack==24.4.2\npathspec==0.12.1\n"}), pkg: "pkg:pypi/pytest@8.2.0", refute: true},
		{name: "uv pip sync --find-links", files: withLock(map[string]string{"requirements.txt": pinnedRuntimeExport, "Dockerfile": "FROM python:3.12\nCOPY requirements.txt .\nRUN uv pip sync --find-links ./wheels requirements.txt\n"}), pkg: "pkg:pypi/black@24.4.2", veto: `--find-links "./wheels"`},
		{name: "uv sync --find-links", files: dockerRun("uv sync --frozen --no-dev --find-links ./wheels"), pkg: "pkg:pypi/pytest@8.2.0", veto: `--find-links "./wheels"`},
		{name: "uv sync with a named remote index stays a fetch option", files: dockerRun("uv sync --frozen --no-dev --index mirror=https://mirror.example.com/simple"), pkg: "pkg:pypi/pytest@8.2.0", refute: true},
		{name: "uv run --default-index into the repository", files: dockerRun("uv run --no-dev --default-index ./simple python -m app"), pkg: "pkg:pypi/pytest@8.2.0", veto: `--default-index "./simple"`},
		{name: "pipenv --pypi-mirror into the repository", files: dockerRun("pipenv sync --pypi-mirror ./mirror"), pkg: "pkg:pypi/pytest@8.2.0", veto: `--pypi-mirror "./mirror"`},
		{name: "ENV PIP_FIND_LINKS into the image", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nENV PIP_FIND_LINKS=/app/wheels\nRUN uv sync --frozen --no-dev\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: `PIP_FIND_LINKS "/app/wheels"`},
		{name: "legacy ENV PIP_FIND_LINKS form", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nENV PIP_FIND_LINKS ./wheels\nRUN uv sync --frozen --no-dev\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: `PIP_FIND_LINKS "./wheels"`},
		{name: "PIP_FIND_LINKS list with one local entry", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nENV PIP_FIND_LINKS=\"https://wheels.example.com/ ./wheels\"\nRUN uv sync --frozen --no-dev\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: `PIP_FIND_LINKS "./wheels"`},
		{name: "workflow env UV_FIND_LINKS", files: withLock(map[string]string{".github/workflows/cd.yml": "name: CD\non: push\nenv:\n  UV_FIND_LINKS: ./wheels\njobs:\n  ship:\n    runs-on: ubuntu-latest\n    steps:\n      - run: uv sync --frozen --no-dev\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: `UV_FIND_LINKS "./wheels"`},
		{name: "an index setting alone makes a file an install surface", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nRUN uv sync --frozen --no-dev\n", "deploy/uv.env": "UV_DEFAULT_INDEX=file:///srv/simple\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: `UV_DEFAULT_INDEX "file:///srv/simple"`},
		{name: "an index setting with an unresolved value", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nENV PIP_INDEX_URL=$MIRROR\nRUN uv sync --frozen --no-dev\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: `PIP_INDEX_URL "$MIRROR"`},
		{name: "remote https index settings stay fetch options", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nENV PIP_INDEX_URL=https://mirror.example.com/simple UV_INDEX_URL=https://mirror.example.com/simple\nRUN uv sync --frozen --no-dev\n"}), pkg: "pkg:pypi/pytest@8.2.0", refute: true},
		{name: "a committed pip.conf with find-links", files: withLock(map[string]string{"pip.conf": "[global]\nfind-links = ./wheels\n", "Dockerfile": "FROM python:3.12\nCOPY pip.conf /etc/pip.conf\nRUN pip install -U pip setuptools wheel\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "pip configuration file"},
		{name: "pip config set find-links", files: dockerRun("pip config set global.find-links /app/wheels && pip install -U pip"), pkg: "pkg:pypi/pytest@8.2.0", veto: "pip config changes"},
		{name: "PIP_CONFIG_FILE", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nENV PIP_CONFIG_FILE=/app/pip.conf\nRUN pip install -U pip\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "PIP_CONFIG_FILE"},
		{name: "uv.toml find-links", files: withLock(map[string]string{"uv.toml": "find-links = [\"./wheels\"]\n", "Dockerfile": "FROM python:3.12\nRUN uv sync --frozen --no-dev\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: `find-links "./wheels"`},
		{name: "[tool.uv.index] into the repository", files: docsUV("default-groups = [\"dev\", \"docs\"]\n\n[[tool.uv.index]]\nname = \"local\"\nurl = \"./simple\"", "uv sync --no-dev --no-group docs"), pkg: "pkg:pypi/mkdocs@1.5.0", veto: `source url "./simple"`},
		{name: "a remote [tool.uv.index] stays a fetch option", files: docsUV("default-groups = [\"dev\", \"docs\"]\n\n[[tool.uv.index]]\nname = \"mirror\"\nurl = \"https://mirror.example.com/simple\"", "uv sync --no-dev --no-group docs"), pkg: "pkg:pypi/mkdocs@1.5.0", refute: true},
		{name: "a poetry source on a file: URL", files: appendFile(docsPoetry(true, "poetry install --without dev"), "pyproject.toml", "\n[[tool.poetry.source]]\nname = \"local\"\nurl = \"file:///srv/wheels\"\n"), pkg: "pkg:pypi/mkdocs@1.5.0", veto: `source url "file:///srv/wheels"`},
		{name: "a remote poetry source stays a fetch option", files: appendFile(docsPoetry(true, "poetry install --without dev"), "pyproject.toml", "\n[[tool.poetry.source]]\nname = \"mirror\"\nurl = \"https://mirror.example.com/simple\"\n"), pkg: "pkg:pypi/mkdocs@1.5.0", refute: true},
		{name: "a pdm source into the repository", files: map[string]string{"pdm.lock": devPDMLock, "app.py": "import requests\n", "Dockerfile": "RUN pdm install --prod\n", "pyproject.toml": "[project]\nname = \"app\"\n\n[[tool.pdm.source]]\nname = \"local\"\nurl = \"./simple\"\n"}, pkg: "pkg:pypi/black@24.4.2", veto: `source url "./simple"`},
		{name: "a Pipfile source into the repository", files: withLock(map[string]string{"Pipfile": "[[source]]\nname = \"local\"\nurl = \"./simple\"\nverify_ssl = false\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: `source url "./simple"`},
		{name: "a pinned runtime export installs the runtime set only", files: withLock(map[string]string{"requirements.txt": pinnedRuntimeExport, "Dockerfile": "FROM python:3.12\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},

		// Build-to-deploy job graphs.
		{name: "a job a deploy job needs is production", files: withLock(map[string]string{".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  package:\n    runs-on: ubuntu-latest\n    steps:\n      - run: uv sync --frozen\n      - run: zip -r app.zip .venv app\n  ship:\n    needs: package\n    runs-on: ubuntu-latest\n    steps:\n      - run: aws lambda update-function-code --function-name x --zip-file fileb://app.zip\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "a reusable workflow called by a deploy is production", files: withLock(map[string]string{".github/workflows/build.yml": "on: workflow_call\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: uv sync --frozen\n", ".github/workflows/main.yml": "on: push\njobs:\n  build:\n    uses: ./.github/workflows/build.yml\n  ship:\n    needs: build\n    environment: production\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./ship.sh\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "a reusable workflow outside the repository", files: withLock(map[string]string{".github/workflows/main.yml": "on: push\njobs:\n  build:\n    uses: acme/ci/.github/workflows/py.yml@v1\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "reusable workflow outside the repository"},

		// Dockerfile paths resolve through COPY and WORKDIR.
		{name: "COPY renames a requirements file", files: withLock(map[string]string{"requirements.txt": pinnedRuntimeExport, "requirements/docker.txt": "black==24.4.2\npathspec==0.12.1\n" + pinnedRuntimeExport, "Dockerfile": "FROM python:3.12\nCOPY requirements/docker.txt requirements.txt\nRUN pip install -r requirements.txt\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "WORKDIR with nothing copied there", files: withLock(map[string]string{"requirements.txt": pinnedRuntimeExport, "deploy/prod.txt": "black==24.4.2\npathspec==0.12.1\n", "prod.txt": pinnedRuntimeExport, "Dockerfile": "FROM python:3.12\nWORKDIR /src/deploy\nRUN pip install -r prod.txt\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "not copied into the image"},
		{name: "WORKDIR resolves through the COPY that fills it", files: withLock(map[string]string{"deploy/prod.txt": "black==24.4.2\npathspec==0.12.1\n", "prod.txt": pinnedRuntimeExport, "Dockerfile": "FROM python:3.12\nCOPY deploy/ /src/deploy/\nWORKDIR /src/deploy\nRUN pip install -r prod.txt\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "a context file that differs between the Dockerfile directory and the root", files: withLock(map[string]string{"docker/Dockerfile": "FROM python:3.12\nCOPY prod.txt .\nRUN pip install -r prod.txt\n", "docker/prod.txt": "black==24.4.2\npathspec==0.12.1\n", "prod.txt": pinnedRuntimeExport}), pkg: "pkg:pypi/black@24.4.2", veto: "which differ"},
		{name: "COPY --from an external image", files: withLock(map[string]string{"Dockerfile": "FROM ghcr.io/acme/py-tools:1 AS tools\nFROM python:3.12\nRUN uv sync --frozen --no-dev\nCOPY --from=ghcr.io/acme/py-tools:1 /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "an image the scanner does not read"},
		{name: "COPY --from a stage of the same Dockerfile", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12 AS build\nCOPY . /app\nWORKDIR /app\nRUN uv sync --frozen --no-dev\nFROM python:3.12-slim\nCOPY --from=build /app/.venv /app/.venv\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "a requirements file copied through a stage", files: withLock(map[string]string{"deploy/base.txt": "black==24.4.2\npathspec==0.12.1\n", "Dockerfile": "FROM python:3.12 AS src\nCOPY deploy/base.txt /req/base.txt\nFROM python:3.12\nCOPY --from=src /req/base.txt /base.txt\nRUN pip install -r /base.txt\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "RUN --mount from an external image", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nRUN --mount=type=bind,from=ghcr.io/acme/wheels:1,target=/w uv sync --frozen --no-dev\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "an image the scanner does not read"},
		{name: "a bind-mounted requirements file", files: withLock(map[string]string{"deploy/base.txt": "black==24.4.2\npathspec==0.12.1\n", "Dockerfile": "FROM python:3.12\nRUN --mount=type=bind,source=deploy/base.txt,target=/tmp/base.txt pip install -r /tmp/base.txt\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "a non-official base image is disclosed", files: withLock(map[string]string{"Dockerfile": "FROM ghcr.io/acme/base:1\nRUN uv sync --frozen --no-dev\n"}), pkg: "pkg:pypi/pytest@8.2.0", refute: true, detail: []string{"packages preinstalled in base images are not read (ghcr.io/acme/base:1)"}},

		// Shapes that stay blocked.
		{name: "a heredoc RUN is read", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nRUN <<EOF\npip install black==24.4.2 pathspec==0.12.1\nEOF\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "a stage's dev sync copied into the final image", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12 AS build\nRUN uv sync --frozen\nFROM python:3.12-slim\nCOPY --from=build /.venv /.venv\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "an ARG in pip install arguments", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nARG EXTRA\nRUN pip install ${EXTRA}\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "variable or substitution"},
		{name: "compose sh -c uv sync --all-groups", files: withLock(map[string]string{"docker-compose.yml": "services:\n  web:\n    command: sh -c \"uv sync --all-groups && python app.py\"\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "a Procfile release step", files: withLock(map[string]string{"Procfile": "release: uv sync --frozen\nweb: gunicorn app:app\n"}), pkg: "pkg:pypi/black@24.4.2", clean: true},
		{name: "poetry --only main --with dev", files: docsPoetry(false, "poetry install --only main --with dev"), pkg: "pkg:pypi/black@24.4.2", clean: true},

		// Group selectors.
		{name: "pdm -G :all", files: map[string]string{"pdm.lock": pdmOptLock, "app.py": "import requests\n", "Dockerfile": "RUN pdm install --prod -G :all\n"}, pkg: "pkg:pypi/pysocks@1.7.1", veto: ":all"},
		{name: "pdm attached -Gsocks keeps the group", files: map[string]string{"pdm.lock": pdmOptLock, "app.py": "import requests\n", "Dockerfile": "RUN pdm install --prod -Gsocks\n"}, pkg: "pkg:pypi/pysocks@1.7.1", clean: true},
		{name: "pdm --prod without the group leaves it out", files: map[string]string{"pdm.lock": pdmOptLock, "app.py": "import requests\n", "Dockerfile": "RUN pdm install --prod\n"}, pkg: "pkg:pypi/pysocks@1.7.1", refute: true},
		{name: "an unparsed option cluster vetoes", files: dockerRun("uv sync -Zq"), pkg: "pkg:pypi/pytest@8.2.0", veto: "uv sync option -Zq"},
		{name: "an installer setting that selects groups", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nENV UV_NO_DEV=0\nRUN uv sync --frozen --no-dev\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "UV_NO_DEV"},

		// Interpreter arguments, read against CPython's option list.
		{name: "python -mpip in a Dockerfile", files: dockerRun("python3.12 -mpip install black==24.4.2"), pkg: "pkg:pypi/black@24.4.2", veto: "pathspec, in the locked closure"},
		{name: "python -mpip -r in a Dockerfile", files: withLock(map[string]string{"requirements-dev.txt": "black==24.4.2\n", "Dockerfile": "FROM python:3.12\nCOPY . .\nRUN python3 -mpip install -r requirements-dev.txt\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pathspec, in the locked closure"},
		{name: "python -mpip in a production workflow", files: withLock(map[string]string{".github/workflows/deploy.yml": "on: push\njobs:\n  d:\n    environment: production\n    runs-on: ubuntu-latest\n    steps:\n      - run: python -mpip install black==24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pathspec, in the locked closure"},
		{name: "python -mpip in a k8s command vector", files: withLock(map[string]string{"deploy/k8s/job.yaml": "command: [\"sh\",\"-c\",\"python -mpip install black==24.4.2\"]\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pathspec, in the locked closure"},
		{name: "pip.exe in a k8s command vector", files: withLock(map[string]string{"deploy/k8s/job.yaml": "command: [\"sh\",\"-c\",\"pip.exe install black==24.4.2\"]\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "pathspec, in the locked closure"},
		{name: "a clustered -Impip", files: dockerRun("python -Impip install black==24.4.2"), pkg: "pkg:pypi/black@24.4.2", veto: "pathspec, in the locked closure"},
		{name: "python -m pip internals", files: dockerRun("python -m pip._internal install black==24.4.2"), pkg: "pkg:pypi/pytest@8.2.0", veto: "-m pip._internal runs an installer module"},
		{name: "an unknown interpreter option", files: pinnedDocker("python3 -Z -m pip install -r requirements.txt"), pkg: "pkg:pypi/black@24.4.2", veto: "python3 -Z is not an interpreter option"},
		{name: "an unknown long interpreter option", files: pinnedDocker("python --frobnicate -m pip install -r requirements.txt"), pkg: "pkg:pypi/black@24.4.2", veto: "python --frobnicate is not an interpreter option"},
		{name: "control: an attached -W value and -mpip parse", files: pinnedDocker("python -Wignore -Bmpip install -r requirements.txt"), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "control: a py launcher version selector parses", files: pinnedDocker("py -3.12 -m pip install -r requirements.txt"), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "control: python -m piptools sync reads its files", files: pinnedDocker("python -m piptools sync requirements.txt"), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "python -m piptools sync of a file naming black", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY . .\nRUN python -m piptools sync requirements/docker.txt\n"), pkg: "pkg:pypi/black@24.4.2"},
		{name: "control: a -W value as its own word, then -m piptools", files: pinnedDocker("python -W ignore -m piptools sync requirements.txt"), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "control: python -I -m pip", files: dockerRun("python -I -m pip install black==24.4.2"), pkg: "pkg:pypi/black@24.4.2", veto: "pathspec, in the locked closure"},
		{name: "control: python3 -u -m pip", files: dockerRun("python3 -u -m pip install black==24.4.2"), pkg: "pkg:pypi/black@24.4.2", veto: "pathspec, in the locked closure"},

		// A requirement file changed between its placement and the install that reads it.
		{name: "cp onto the file in the same RUN", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY . .\nRUN cp requirements/docker.txt requirements.txt && pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "runs cp, which is not known to leave it as it is"},
		{name: "mv onto the file in an earlier RUN", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY . .\nRUN mv requirements/docker.txt requirements.txt\nRUN pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "runs mv"},
		{name: "an append redirect onto the file", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY . .\nRUN echo black==24.4.2 >> requirements.txt && pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "runs a redirect to requirements.txt"},
		{name: "sed -i on the file", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY . .\nRUN sed -i '$ a black==24.4.2' requirements.txt && pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "runs sed"},
		{name: "cp onto the file in a shell script", files: rewrittenReqs("deploy.sh", "cp requirements/docker.txt requirements.txt\npip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "may be changed before it is read"},
		{name: "cp onto the file in an earlier step of a production job", files: rewrittenReqs(".github/workflows/deploy.yml", "on: push\njobs:\n  d:\n    environment: production\n    runs-on: ubuntu-latest\n    steps:\n      - run: cp requirements/docker.txt requirements.txt\n      - run: pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "may be changed before it is read"},
		{name: "cp onto the file in an earlier GitLab script line", files: rewrittenReqs(".gitlab-ci.yml", "deploy:\n  script:\n    - cp requirements/docker.txt requirements.txt\n    - pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "may be changed before it is read"},
		{name: "cp onto the file in a stage built on the one that copies it", files: rewrittenReqs("Dockerfile", "FROM python:3.12 AS base\nCOPY . .\nFROM base\nRUN cp requirements/docker.txt requirements.txt\nRUN pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "runs cp"},
		{name: "a command off the allow-list between COPY and install", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY . .\nRUN make deps\nRUN pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "runs make"},
		{name: "a redirect to a variable", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY . .\nRUN echo black==24.4.2 > $REQS && pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "runs a redirect to $REQS"},
		{name: "an output option onto the file", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY . .\nRUN uv pip compile requirements/docker.txt -o requirements.txt && pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "runs -o requirements.txt"},
		{name: "a CMD that rewrites the file before installing", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY . .\nCMD cp requirements/docker.txt requirements.txt && pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "runs cp"},
		{name: "a second COPY of a different file onto it", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY requirements/docker.txt requirements.txt\nCOPY . .\nRUN pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", veto: "placed by more than one COPY of different files"},
		{name: "control: a second COPY of the same file", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY requirements.txt .\nCOPY . .\nRUN pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "control: inert commands between COPY and install", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nCOPY . .\nRUN set -eux && mkdir -p /data && echo ok > /dev/null && chmod 644 requirements.txt && [ -f requirements.txt ]\nRUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*\nRUN python -m venv /venv && . /venv/bin/activate && pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "control: a file written before the COPY that places it", files: rewrittenReqs("Dockerfile", "FROM python:3.12\nWORKDIR /app\nRUN make deps\nCOPY . .\nRUN pip install -r requirements.txt\n"), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "control: inert commands in a shell script", files: rewrittenReqs("deploy.sh", "#!/bin/sh\nset -eu\necho installing\nif [ -f requirements.txt ]; then\n  pip install -r requirements.txt\nfi\n"), pkg: "pkg:pypi/black@24.4.2", refute: true},

		// Installer configuration placed into the image or named by a command.
		{name: "a pip config copied to /etc/pip.conf", files: pipConfigCopy("docker/pip.conf.prod", "/etc/pip.conf"), pkg: "pkg:pypi/black@24.4.2", veto: "places /etc/pip.conf"},
		{name: "a pip config copied to ~/.config/pip", files: pipConfigCopy("docker/pipcfg", "/root/.config/pip/pip.conf"), pkg: "pkg:pypi/black@24.4.2", veto: "places /root/.config/pip/pip.conf"},
		{name: "a uv config copied to /etc/uv", files: pipConfigCopy("docker/pipcfg", "/etc/uv/uv.toml"), pkg: "pkg:pypi/black@24.4.2", veto: "places /etc/uv/uv.toml"},
		{name: "a file copied to a variable name", files: pipConfigCopy("docker/pipcfg", "/etc/${CONF}"), pkg: "pkg:pypi/black@24.4.2", veto: "a file name the scanner cannot read"},
		{name: "a pip config written by RUN", files: withLock(map[string]string{"requirements.txt": pinnedRuntimeExport, "requirements-dev.txt": "black==24.4.2\n", "docker/pipcfg": "[install]\nrequirement = /src/requirements-dev.txt\n", "Dockerfile": "FROM python:3.12\nCOPY . /src\nRUN cp /src/docker/pipcfg /etc/pip.conf && pip install -r /src/requirements.txt\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "names /etc/pip.conf"},
		{name: "PIP_CONFIG_FILE as a build argument", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nARG PIP_CONFIG_FILE=/src/docker/pipcfg\nCOPY . /src\nRUN pip install -r /src/requirements.txt\n", "requirements.txt": pinnedRuntimeExport}), pkg: "pkg:pypi/black@24.4.2", veto: "sets PIP_CONFIG_FILE"},
		{name: "a PIP_ setting off the allow-list", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nENV PIP_FROBNICATE=1\nCOPY . /src\nRUN pip install -r /src/requirements.txt\n", "requirements.txt": pinnedRuntimeExport}), pkg: "pkg:pypi/black@24.4.2", veto: "sets PIP_FROBNICATE"},
		{name: "control: a PIP_ setting on the allow-list", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nENV PIP_NO_CACHE_DIR=1\nCOPY . /src\nRUN pip install -r /src/requirements.txt\n", "requirements.txt": pinnedRuntimeExport}), pkg: "pkg:pypi/black@24.4.2", refute: true},
		{name: "UV_CONFIG_FILE", files: withLock(map[string]string{"Dockerfile": "FROM python:3.12\nCOPY . .\nENV UV_CONFIG_FILE=/docker/uvcfg\nRUN uv sync --frozen --no-dev\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "UV_CONFIG_FILE"},
		{name: "UV_CONFIG_FILE in a manifest that is a candidate only by content", files: withLock(map[string]string{"deploy/k8s/env.yaml": "env:\n  - name: UV_CONFIG_FILE\n    value: /cfg/uvcfg\n"}), pkg: "pkg:pypi/black@24.4.2", veto: "UV_CONFIG_FILE"},
		{name: "uv --config-file", files: dockerRun("uv --config-file docker/uvcfg sync --frozen --no-dev"), pkg: "pkg:pypi/black@24.4.2", veto: "uv --config-file"},
		{name: "control: another config copied into /etc", files: pipConfigCopy("docker/pipcfg", "/etc/app.conf"), pkg: "pkg:pypi/black@24.4.2", refute: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := reachFor(t, tc.files, tc.pkg)
			if got := res.Refutation != nil; got != tc.refute {
				t.Fatalf("refuted = %v, want %v (refutation %+v)", got, tc.refute, res.Refutation)
			}
			if tc.refute {
				for _, want := range append([]string{devAssumption}, tc.detail...) {
					if !strings.Contains(res.Refutation.Detail, want) {
						t.Errorf("detail %q lacks %q", res.Refutation.Detail, want)
					}
				}
			}
			ls := scanFor(t, tc.files)
			found := false
			for _, m := range ls.markerless {
				found = found || (tc.veto != "" && strings.Contains(m, tc.veto))
			}
			if tc.veto != "" && !found {
				t.Errorf("scan vetoes %v, want one containing %q", ls.markerless, tc.veto)
			}
			if tc.veto == "" && (tc.refute || tc.clean) && len(ls.markerless) > 0 {
				t.Errorf("scan vetoes %v, want none", ls.markerless)
			}
		})
	}
}

// TestLoadSet_UnreadableRequirementFile pins that a requirement file an install reads but the
// scan cannot open blocks every refutation.
func TestLoadSet_UnreadableRequirementFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads a mode-000 file")
	}
	files := withLock(map[string]string{"Dockerfile": "FROM python:3.12\nCOPY deploy/ deploy/\nRUN pip install -r deploy/base.txt\n", "deploy/base.txt": "black==24.4.2\npathspec==0.12.1\n"})
	dir := writeTree(t, files)
	f := filepath.Join(dir, "deploy", "base.txt")
	if err := os.Chmod(f, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f, 0o644) })
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Package: "pkg:pypi/pytest@8.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Refutation != nil {
		t.Fatalf("an unreadable requirement file must block refutation; got %+v", res.Refutation)
	}
}

// TestLoadSet_UnreadableFile pins that a file the scan cannot open blocks every refutation,
// whatever its name: it may carry install commands.
func TestLoadSet_UnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads a mode-000 file")
	}
	for _, unreadable := range []bool{false, true} {
		dir := writeTree(t, withLock(map[string]string{"deploy/run.sh": "exec gunicorn app:app\n"}))
		f := filepath.Join(dir, "deploy", "run.sh")
		if unreadable {
			if err := os.Chmod(f, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(f, 0o644) })
		}
		res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Package: "pkg:pypi/pytest@8.2.0"})
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Refutation != nil; got == unreadable {
			t.Fatalf("unreadable=%v: refuted=%v; an unreadable file must block refutation and a readable one must not", unreadable, got)
		}
		if !unreadable {
			continue
		}
		ls := &loadSet{complete: true, reqRuntime: map[string]bool{}, installed: map[string]bool{}, projectNames: map[string]bool{}}
		ls.locks = loadLocks(dir, ls)
		ls.scanInstalls(dir)
		found := false
		for _, m := range ls.markerless {
			found = found || strings.Contains(m, "deploy/run.sh: could not be read")
		}
		if !found {
			t.Errorf("vetoes %v, want one containing %q", ls.markerless, "deploy/run.sh: could not be read")
		}
	}
}

// TestLoadSet_UnreadableDirectory pins that a directory the walks cannot read blocks every
// refutation: it may hold install commands or an installed copy.
func TestLoadSet_UnreadableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads a mode-000 directory")
	}
	cases := []struct {
		name, dir, veto string
		committed       bool
	}{
		{name: "a build directory", dir: "deploy", veto: "deploy: could not be read: install commands"},
		{name: "the workflows directory", dir: ".github/workflows", veto: ".github/workflows: could not be read: install commands"},
		{name: "a vendor directory", dir: "lib", veto: "lib: could not be read: installed copies", committed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, withLock(map[string]string{tc.dir + "/README": "x\n"}))
			d := filepath.Join(dir, filepath.FromSlash(tc.dir))
			if err := os.Chmod(d, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(d, 0o755) })
			// The source walk errors on a non-hidden unreadable directory, which refutes nothing
			// either; the scan's own veto is pinned below.
			res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Package: "pkg:pypi/pytest@8.2.0"})
			if err == nil && res.Refutation != nil {
				t.Fatalf("an unreadable directory must block refutation; got %+v", res.Refutation)
			}
			ls := &loadSet{complete: true, reqRuntime: map[string]bool{}, installed: map[string]bool{}, projectNames: map[string]bool{}}
			ls.locks = loadLocks(dir, ls)
			if tc.committed {
				ls.committedInstalls(dir)
			} else {
				ls.scanInstalls(dir)
			}
			found := false
			for _, m := range ls.markerless {
				found = found || strings.Contains(m, tc.veto)
			}
			if !found {
				t.Errorf("vetoes %v, want one containing %q", ls.markerless, tc.veto)
			}
		})
	}
}

// TestLoadSet_RequirementFileOutsideRepo pins that a requirement file outside the repository
// blocks every refutation even when it exists on the build host.
func TestLoadSet_RequirementFileOutsideRepo(t *testing.T) {
	files := map[string]string{"shared/requirements.txt": "black==24.4.2\n"}
	for k, v := range withLock(map[string]string{"deploy.sh": "pip install -r ../shared/requirements.txt\n"}) {
		files["repo/"+k] = v
	}
	root := writeTree(t, files)
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: filepath.Join(root, "repo"), Package: "pkg:pypi/pytest@8.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Refutation != nil {
		t.Fatalf("a requirement file outside the repository must block refutation; got %+v", res.Refutation)
	}
}

// TestLoadSet_ProjectCoverage pins B3 and B4: a lockfile covers only its own project and
// declared workspace members, and a distribution the repository carries installed never
// refutes.
func TestLoadSet_ProjectCoverage(t *testing.T) {
	cases := []struct {
		name   string
		files  map[string]string
		pkg    string
		refute bool
	}{
		{name: "nested setup.py outside the workspace members", files: withLock(map[string]string{"services/worker/setup.py": "from setuptools import setup\nsetup(name='worker', install_requires=['black'])\n", "services/worker/worker/__init__.py": ""}), pkg: "pkg:pypi/pytest@8.2.0"},
		{name: "nested setup.cfg outside the workspace members", files: withLock(map[string]string{"services/worker/setup.cfg": "[metadata]\nname = worker\n\n[options]\ninstall_requires =\n    black\n"}), pkg: "pkg:pypi/pytest@8.2.0"},
		{name: "nested poetry project outside the workspace members", files: withLock(map[string]string{"services/worker/pyproject.toml": "[tool.poetry]\nname = \"worker\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\nblack = \"*\"\n"}), pkg: "pkg:pypi/pytest@8.2.0"},
		{name: "nested [project] outside the workspace members", files: withLock(map[string]string{"services/worker/pyproject.toml": "[project]\nname = \"worker\"\ndependencies = [\"black\"]\n"}), pkg: "pkg:pypi/pytest@8.2.0"},
		{name: "a declared workspace member's project is covered", files: func() map[string]string {
			f := withLock(map[string]string{"pkgs/worker/pyproject.toml": "[project]\nname = \"worker\"\ndependencies = [\"requests\"]\n"})
			f["uv.lock"] = strings.Replace(strings.Replace(loadsetLock, `members = ["app"]`, `members = ["app", "worker"]`, 1), "[[package]]\nname = \"requests\"",
				"[[package]]\nname = \"worker\"\nversion = \"0.1.0\"\nsource = { editable = \"pkgs/worker\" }\ndependencies = [{ name = \"requests\" }]\n\n[[package]]\nname = \"requests\"", 1)
			return f
		}(), pkg: "pkg:pypi/pytest@8.2.0", refute: true},
		{name: "a root poetry dependency is a runtime name", files: map[string]string{"app.py": "import requests\n", "poetry.lock": devPoetryLock,
			"pyproject.toml": "[tool.poetry]\nname = \"app\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"*\"\nblack = \"*\"\n"}, pkg: "pkg:pypi/black@24.4.2"},
		{name: "committed dist-info under lib/", files: withLock(map[string]string{"app/main.py": "import requests\nimport django\n", "lib/black-24.4.2.dist-info/METADATA": "Metadata-Version: 2.1\nName: black\nVersion: 24.4.2\n", "lib/black/__init__.py": ""}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "committed dist-info outside any vendor dir", files: withLock(map[string]string{"deploy/pkgs/Black-24.4.2.dist-info/RECORD": ""}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "committed egg-info", files: withLock(map[string]string{"build/black.egg-info/PKG-INFO": "Metadata-Version: 1.0\nName: black\n"}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "vendored package without metadata", files: withLock(map[string]string{"vendor/black/__init__.py": ""}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "a dist-info under tests/ is read: only node_modules and site-packages are skipped", files: withLock(map[string]string{"tests/fixtures/black-24.4.2.dist-info/METADATA": "Name: black\n"}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "a committed site-packages' packages are installed", files: withLock(map[string]string{"venv/lib/python3.12/site-packages/black/__init__.py": ""}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "a committed wheel is installed", files: withLock(map[string]string{"wheels/black-24.4.2-py3-none-any.whl": "PK"}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "a Lambda layer's python/ is vendored code", files: withLock(map[string]string{"layer/python/black/__init__.py": ""}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "nested [project] with dynamic dependencies", files: withLock(map[string]string{"services/worker/pyproject.toml": "[project]\nname = \"w\"\ndynamic = [\"dependencies\"]\n[tool.setuptools.dynamic]\ndependencies = {file = [\"deps.in\"]}\n", "services/worker/deps.in": "black\n"}), pkg: "pkg:pypi/black@24.4.2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := reachFor(t, tc.files, tc.pkg)
			if got := res.Refutation != nil; got != tc.refute {
				t.Fatalf("refuted = %v, want %v (refutation %+v)", got, tc.refute, res.Refutation)
			}
		})
	}
}

// TestCallGraph_ScopedSitesStayRunWide pins that the CallGraph op alone (no load set) keeps
// the run-wide dynamic_import reason for a scoped site; only Reachability narrows it.
func TestCallGraph_ScopedSitesStayRunWide(t *testing.T) {
	dir := writeTree(t, withLock(map[string]string{"app/plug.py": "from requests import *\n"}))
	cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(cg.Partiality, plugin.PartialReasonDynamicImportSpecifier) {
		t.Fatalf("CallGraph must keep dynamic_import for a star import; got %v", cg.Partiality.Reasons)
	}
}

// TestLoadSet_UnpinnedExportReasonIsStable pins that the requirements-export reason names the
// first unpinned edge in sorted order, whatever the map order.
// TestLoadSet_ExportIndexOption pins that a requirements export pointing pip at an index that
// is not a remote https index is not an export of locked copies, and a remote one still is.
func TestLoadSet_ExportIndexOption(t *testing.T) {
	ls := &loadSet{locks: &lockModel{versions: map[string]map[string]bool{"alpha": {"1.0": true}}}}
	for opt, want := range map[string]string{
		"--index-url ./simple":                          "option --index-url is not a remote https index",
		"-i file:///srv/simple":                         "option -i is not a remote https index",
		"--extra-index-url=http://mirror.example.com":   "option --extra-index-url is not a remote https index",
		"--index-url https://mirror.example.com/simple": "",
	} {
		if got := ls.unpinnedExport([]byte(opt + "\nalpha==1.0\n")); got != want {
			t.Errorf("%s: unpinnedExport = %q, want %q", opt, got, want)
		}
	}
}

func TestLoadSet_UnpinnedExportReasonIsStable(t *testing.T) {
	ls := &loadSet{locks: &lockModel{
		versions: map[string]map[string]bool{
			"alpha": {"1.0": true}, "bravo": {"1.0": true}, "charlie": {"1.0": true},
			"delta": {"1.0": true}, "echo": {"1.0": true}, "foxtrot": {"1.0": true},
		},
		edges: map[string]map[string]bool{
			"alpha": {"zulu": true, "yankee": true}, "bravo": {"xray": true},
			"charlie": {"whiskey": true}, "delta": {"victor": true},
			"echo": {"uniform": true}, "foxtrot": {"tango": true},
		},
	}}
	data := []byte("foxtrot==1.0\necho==1.0\ndelta==1.0\ncharlie==1.0\nbravo==1.0\nalpha==1.0\n")
	const want = "alpha depends on yankee, which the file does not pin"
	for i := 0; i < 50; i++ {
		if got := ls.unpinnedExport(data); got != want {
			t.Fatalf("run %d: unpinnedExport = %q, want %q", i, got, want)
		}
	}
}

func TestStaticImports(t *testing.T) {
	src := "import a.b, c as d\nfrom e import f, g as h\nfrom .rel import x\nfrom ..up import *\ntry: import j\nexcept ImportError: pass\nx = 1; import k\n"
	mods, stars := staticImports(logicalLines(src))
	want := []string{"..up", ".rel", "a.b", "c", "e", "e.f", "e.g", "j", "k"}
	if strings.Join(mods, ",") != strings.Join(want, ",") {
		t.Errorf("mods = %v, want %v", mods, want)
	}
	if strings.Join(stars, ",") != "..up" {
		t.Errorf("stars = %v", stars)
	}
}
