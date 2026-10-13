package pythonanalysis

import (
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

// TestLoadSet_RuntimeUnloadedSwitch measures option B: with refuteRuntimeUnloaded set, a
// runtime distribution no root loads refutes when no loader could reach it, and the Detail
// says it is in the runtime install.
func TestLoadSet_RuntimeUnloadedSwitch(t *testing.T) {
	prev := refuteRuntimeUnloaded
	refuteRuntimeUnloaded = "1"
	t.Cleanup(func() { refuteRuntimeUnloaded = prev })

	res := reachFor(t, withLock(nil), "pkg:pypi/click@8.1.7")
	if res.Refutation == nil || !strings.Contains(res.Refutation.Detail, "in the runtime install") {
		t.Fatalf("B must refute runtime-unloaded click; got %+v", res.Refutation)
	}
	if strings.Contains(res.Refutation.Detail, devAssumption) {
		t.Errorf("a class (ii) detail must not claim the dev-group assumption: %q", res.Refutation.Detail)
	}
	// A distribution an install command names, or the repository carries installed, is never
	// refuted, not even as runtime-unloaded.
	for name, files := range map[string]map[string]string{
		"pip install": dockerRun("pip install black==24.4.2"),
		"dist-info":   withLock(map[string]string{"lib/black-24.4.2.dist-info/METADATA": "Name: black\n"}),
	} {
		if res := reachFor(t, files, "pkg:pypi/black@24.4.2"); res.Refutation != nil {
			t.Errorf("%s: an installed distribution must not refute under B; got %+v", name, res.Refutation)
		}
	}
	// An unbounded loader in the load set marks the whole runtime install loaded: B refutes nothing.
	res = reachFor(t, withLock(map[string]string{"app/llm.py": "import litellm\n"}), "pkg:pypi/click@8.1.7")
	if res.Refutation != nil {
		t.Fatalf("an unbounded loader must block B; got %+v", res.Refutation)
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
			detail: []string{"install commands checked in 1 build, deploy and CI files (docker-compose.yml)"}},
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
		{name: "no install surface: detail says so", files: withLock(nil), pkg: "pkg:pypi/black@24.4.2", refute: true, detail: []string{"no build, deploy or CI files to check for install commands"}},

		// Named distributions: blocked with their lockfile closure, in any job.
		{name: "pip install names black", files: dockerRun("pip install black==24.4.2"), pkg: "pkg:pypi/black@24.4.2"},
		{name: "pip install of black leaves pytest refutable", files: dockerRun("pip install black==24.4.2"), pkg: "pkg:pypi/pytest@8.2.0", refute: true},
		{name: "pip install of black blocks its closure", files: dockerRun("pip install black==24.4.2"), pkg: "pkg:pypi/pathspec@0.12.1"},
		{name: "pip3 install names black", files: dockerRun("pip3 install --no-cache-dir Black"), pkg: "pkg:pypi/black@24.4.2"},
		{name: "python -m pip install names black", files: dockerRun("python3.12 -m pip install -U black"), pkg: "pkg:pypi/black@24.4.2"},
		{name: "uv pip install names black", files: dockerRun("uv pip install --system black"), pkg: "pkg:pypi/black@24.4.2"},
		{name: "pip install -r reads the file", files: withLock(map[string]string{"Dockerfile": "RUN pip install -r deploy/base.txt\n", "deploy/base.txt": "black==24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2"},
		{name: "pip install -r leaves unnamed pytest refutable", files: withLock(map[string]string{"Dockerfile": "RUN pip install -r deploy/base.txt\n", "deploy/base.txt": "black==24.4.2\n"}), pkg: "pkg:pypi/pytest@8.2.0", refute: true},
		{name: "pipx install names black", files: dockerRun("pipx install black"), pkg: "pkg:pypi/black@24.4.2"},
		{name: "uvx names black", files: dockerRun("uvx black --check ."), pkg: "pkg:pypi/black@24.4.2"},
		{name: "a test CI job's install still names black", files: withLock(map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    environment: test\n    steps:\n      - run: pip install black==24.4.2\n"}), pkg: "pkg:pypi/black@24.4.2"},
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
		{name: "pip install of a name the lockfile does not lock", files: dockerRun("pip install flask"), pkg: "pkg:pypi/pytest@8.2.0", veto: "flask is not locked"},
		{name: "pip install -r from a URL", files: dockerRun("pip install -r https://example.com/requirements.txt"), pkg: "pkg:pypi/pytest@8.2.0", veto: "is a URL"},
		{name: "pip install -r of a missing file", files: dockerRun("pip install -r requirements-prod.txt"), pkg: "pkg:pypi/pytest@8.2.0", veto: "not in the repository"},
		{name: "pip install -r of a file outside the repository", files: dockerRun("pip install -r ../shared/requirements.txt"), pkg: "pkg:pypi/pytest@8.2.0", veto: "not in the repository"},
		{name: "pip install -r of a file with an editable line", files: withLock(map[string]string{"Dockerfile": "RUN pip install -r deploy/base.txt\n", "deploy/base.txt": "-e ./lib\n"}), pkg: "pkg:pypi/pytest@8.2.0", veto: "deploy/base.txt"},
		{name: "pip install --no-deps alongside another pip install", files: dockerRun("pip install --no-deps black==24.4.2 && pip install requests==2.31.0"), pkg: "pkg:pypi/pytest@8.2.0", veto: "--no-deps"},
		{name: "a lockfile install with no lockfile of its format", files: dockerRun("poetry install --only main"), pkg: "pkg:pypi/pytest@8.2.0", veto: "no poetry lockfile"},
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
			if tc.veto == "" && tc.refute && len(ls.markerless) > 0 {
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
	files := withLock(map[string]string{"Dockerfile": "RUN pip install -r deploy/base.txt\n", "deploy/base.txt": "black==24.4.2\n"})
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

// TestLoadSet_RequirementFileOutsideRepo pins that a requirement file outside the repository
// blocks every refutation even when it exists on the build host.
func TestLoadSet_RequirementFileOutsideRepo(t *testing.T) {
	files := map[string]string{"shared/requirements.txt": "black==24.4.2\n"}
	for k, v := range withLock(map[string]string{"Dockerfile": "RUN pip install -r ../shared/requirements.txt\n"}) {
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
		{name: "a test fixture's dist-info is not installed", files: withLock(map[string]string{"tests/fixtures/black-24.4.2.dist-info/METADATA": "Name: black\n"}), pkg: "pkg:pypi/black@24.4.2", refute: true},
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
