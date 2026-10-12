package pythonanalysis

import (
	"context"
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
			name:  "enumerating loader marks its drivers loaded and emits a bounded scoped limit",
			files: withLock(map[string]string{"app/db.py": "import sqlalchemy\n"}), pkg: "pkg:pypi/asyncpg@0.29.0",
			scoped: "pkg:pypi/sqlalchemy",
		},
		{
			name:  "unbounded loader's Targets exclude dev groups, so a dev distribution still refutes",
			files: withLock(map[string]string{"app/llm.py": "import litellm\n"}), pkg: "pkg:pypi/black@24.4.2",
			refute: true, purl: "pkg:pypi/black", scoped: "pkg:pypi/litellm", noScope: true,
			detail: []string{"loaders expanded: litellm"},
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
			pkg: "pkg:pypi/black@24.4.2", refute: true, purl: "pkg:pypi/black",
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
	// An unbounded loader in the load set targets the whole runtime install: B refutes nothing.
	res = reachFor(t, withLock(map[string]string{"app/llm.py": "import litellm\n"}), "pkg:pypi/click@8.1.7")
	if res.Refutation != nil {
		t.Fatalf("an unbounded loader must block B; got %+v", res.Refutation)
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
