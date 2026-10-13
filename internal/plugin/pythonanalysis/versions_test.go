package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func resolveVersion(t *testing.T, dir, coordinate string) plugin.DependencyVersionResult {
	t.Helper()
	res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{
		BuildDir:   dir,
		Coordinate: coordinate,
	})
	if err != nil {
		t.Fatalf("ResolveDependencyVersions: %v", err)
	}
	return res
}

func TestResolveVersions_RequirementsTxt(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"requirements.txt": `# app deps
DeepDiff==8.0.1 --hash=sha256:abc123
flask>=2.0            # a range, not a pin → UNRESOLVED
smolagents==1.2.3 ; python_version >= "3.10"
Pillow[extra]==9.0.0
-r other.txt
git+https://github.com/x/y.git#egg=z
`,
	})
	res := resolveVersion(t, dir, "deepdiff")
	if !res.Found || !res.Match.Resolved || res.Match.Version != "8.0.1" {
		t.Fatalf("DeepDiff pin want 8.0.1 resolved; got %+v", res.Match)
	}
	// hashed pin + env marker stripped
	if r := resolveVersion(t, dir, "smolagents"); !r.Match.Resolved || r.Match.Version != "1.2.3" {
		t.Fatalf("smolagents want 1.2.3; got %+v", r.Match)
	}
	// extras stripped
	if r := resolveVersion(t, dir, "pillow"); !r.Match.Resolved || r.Match.Version != "9.0.0" {
		t.Fatalf("Pillow want 9.0.0; got %+v", r.Match)
	}
	// a range is UNRESOLVED — fail open, never a fabricated version
	if r := resolveVersion(t, dir, "flask"); r.Match.Resolved {
		t.Fatalf("flask range must be UNRESOLVED; got %+v", r.Match)
	}
}

func TestResolveVersions_PoetryLock(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"poetry.lock": `
[[package]]
name = "deepdiff"
version = "8.0.1"
description = "x"

[[package]]
name = "flask"
version = "2.3.0"

[metadata]
lock-version = "2.0"
`,
	})
	if r := resolveVersion(t, dir, "DeepDiff"); !r.Match.Resolved || r.Match.Version != "8.0.1" {
		t.Fatalf("poetry DeepDiff want 8.0.1; got %+v", r.Match)
	}
	if r := resolveVersion(t, dir, "flask"); !r.Match.Resolved || r.Match.Version != "2.3.0" {
		t.Fatalf("poetry flask want 2.3.0; got %+v", r.Match)
	}
}

func TestResolveVersions_PipfileLock(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"Pipfile.lock": `{
  "default": {
    "deepdiff": {"version": "==8.0.1"},
    "flask": {"version": "==2.3.0"}
  },
  "develop": {
    "pytest": {"version": "==8.1.0"}
  }
}`,
	})
	if r := resolveVersion(t, dir, "deepdiff"); !r.Match.Resolved || r.Match.Version != "8.0.1" {
		t.Fatalf("Pipfile DeepDiff want 8.0.1; got %+v", r.Match)
	}
	if r := resolveVersion(t, dir, "pytest"); !r.Match.Resolved || r.Match.Version != "8.1.0" {
		t.Fatalf("Pipfile dev pytest want 8.1.0; got %+v", r.Match)
	}
}

func TestResolveVersions_Pyproject_ExactPinOnly(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pyproject.toml": `
[project]
name = "app"
dependencies = [
    "deepdiff==8.0.1",
    "flask>=2.0",
]
`,
	})
	if r := resolveVersion(t, dir, "deepdiff"); !r.Match.Resolved || r.Match.Version != "8.0.1" {
		t.Fatalf("pyproject DeepDiff exact pin want 8.0.1; got %+v", r.Match)
	}
	if r := resolveVersion(t, dir, "flask"); r.Match.Resolved {
		t.Fatalf("pyproject flask range must be UNRESOLVED; got %+v", r.Match)
	}
}

// PEP 503 name normalization: "Deep_Diff" in the manifest matches a "deep-diff" query.
func TestResolveVersions_NameNormalization(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"requirements.txt": "Deep_Diff==8.0.1\n",
	})
	if r := resolveVersion(t, dir, "deep-diff"); !r.Match.Resolved || r.Match.Version != "8.0.1" {
		t.Fatalf("normalized name match want 8.0.1; got %+v", r.Match)
	}
}

// A build dir with no manifest degrades to declared-partial (no_manifest) — a normal repo
// shape must not turn the run red. The recognized manifest set already covers the DECLARED
// manifests (pyproject.toml, requirements*.txt), so there is nothing to seed; the partiality
// is the entire soundness guarantee.
func TestResolveVersions_NoManifest_DegradesToPartial(t *testing.T) {
	dir := writeTree(t, map[string]string{"m.py": "x = 1\n"})
	res := resolveVersion(t, dir, "flask") // resolveVersion t.Fatals on a hard error

	if res.Partiality.Complete {
		t.Fatal("no manifest must never report Complete — it must be distinguishable from a clean scan")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoManifest) {
		t.Fatalf("Reasons = %v, want %q", res.Partiality.Reasons, plugin.PartialReasonNoManifest)
	}
	if len(res.All) != 0 {
		t.Fatalf("nothing is declared, so nothing may be reported; All=%+v", res.All)
	}
	if res.Found {
		t.Fatalf("no manifest cannot make a coordinate Found; got %+v", res.Match)
	}
}

// A missing build dir stays a hard error (inv.4) — only the no-manifest branch degrades.
func TestResolveVersions_MissingBuildDirIsHardError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nope")
	if _, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir}); err == nil {
		t.Fatal("a missing build dir must be a hard error")
	}
}

// A coordinate declared nowhere is Found=false (not an error).
func TestResolveVersions_Absent(t *testing.T) {
	dir := writeTree(t, map[string]string{"requirements.txt": "flask==2.3.0\n"})
	if r := resolveVersion(t, dir, "nonexistent"); r.Found {
		t.Fatalf("absent coordinate must be Found=false; got %+v", r)
	}
}

// Declared-specifier readers: a range is carried in Constraint with Resolved=false and never
// becomes Version; an exact pin keeps resolving; a non-requirement is not read as one.
func TestResolveVersions_DeclaredConstraint(t *testing.T) {
	const (
		setupCfg = `[metadata]
name = app

[options]
packages = find:
install_requires =
    requests>=2.31,<3
    click==8.1.7
    # a comment line
    importlib-metadata; python_version<"3.8"

[options.extras_require]
test = pytest>=7.0; coverage
`
		setupPy = `from setuptools import setup

deps = compute()

setup(
    name="app",
    install_requires=[
        "jinja2>=3.0.0",  # templating
        'markupsafe==2.1.3',
        "pydantic (>=2.3)",
    ],
    tests_require=["nose>=1"],
)
`
		setupPyComputed = `from setuptools import setup
setup(name="app", install_requires=["aiohttp>=3.9", extra()])
`
		pyproject = `[project]
name = "app"
dependencies = [
    "flask>=2.0,<3",
    "deepdiff==8.0.1",
    "wheelpkg @ https://example.com/wheelpkg-1.0-py3-none-any.whl",
]

[project.optional-dependencies]
dev = ["pytest >= 7.0"]
`
		hatchBuild = `"""Custom build hook. Nothing>=here is a requirement."""
import os

DEPENDENCIES = [
    "aiohttp>=3.9.2",
    "jinja2>=3.0.0",
    "rich-argparse>=1.0.0",
]
SETTINGS = {"plain_name": "value", "path": "airflow/www"}
VERSIONED = f"pendulum>={os.environ.get('V')}"
python_req = "python_version >= '3.9'"
`
		requirements = "flask>=2.0\nrequests==2.31.0\nurllib3 (>=1.26)\n"
	)
	tests := []struct {
		name           string
		files          map[string]string
		coord          string
		wantFound      bool
		wantResolved   bool
		wantVersion    string
		wantConstraint string
	}{
		{"setup.cfg dangling range", map[string]string{"setup.cfg": setupCfg}, "requests", true, false, "", ">=2.31,<3"},
		{"setup.cfg exact pin resolves", map[string]string{"setup.cfg": setupCfg}, "click", true, true, "8.1.7", ""},
		{"setup.cfg bare name with marker", map[string]string{"setup.cfg": setupCfg}, "importlib-metadata", true, false, "", ""},
		{"setup.cfg extras_require semicolon list", map[string]string{"setup.cfg": setupCfg}, "pytest", true, false, "", ">=7.0"},
		{"setup.cfg extras_require second entry", map[string]string{"setup.cfg": setupCfg}, "coverage", true, false, "", ""},
		{"setup.py literal range", map[string]string{"setup.py": setupPy}, "jinja2", true, false, "", ">=3.0.0"},
		{"setup.py literal exact pin", map[string]string{"setup.py": setupPy}, "markupsafe", true, true, "2.1.3", ""},
		{"setup.py parenthesized specifier", map[string]string{"setup.py": setupPy}, "pydantic", true, false, "", ">=2.3"},
		{"setup.py other keyword not read", map[string]string{"setup.py": setupPy}, "nose", false, false, "", ""},
		{"setup.py computed list rejected whole", map[string]string{"setup.py": setupPyComputed}, "aiohttp", false, false, "", ""},
		{"PEP 621 multi-clause range kept whole", map[string]string{"pyproject.toml": pyproject}, "flask", true, false, "", ">=2.0,<3"},
		{"PEP 621 exact pin resolves", map[string]string{"pyproject.toml": pyproject}, "deepdiff", true, true, "8.0.1", ""},
		{"PEP 621 direct reference has no constraint", map[string]string{"pyproject.toml": pyproject}, "wheelpkg", true, false, "", ""},
		{"PEP 621 optional-dependencies", map[string]string{"pyproject.toml": pyproject}, "pytest", true, false, "", ">=7.0"},
		{"hatch_build literal requirement", map[string]string{"hatch_build.py": hatchBuild}, "aiohttp", true, false, "", ">=3.9.2"},
		{"hatch_build second literal", map[string]string{"hatch_build.py": hatchBuild}, "jinja2", true, false, "", ">=3.0.0"},
		{"hatch_build bare word not a requirement", map[string]string{"hatch_build.py": hatchBuild}, "plain-name", false, false, "", ""},
		{"hatch_build f-string skipped", map[string]string{"hatch_build.py": hatchBuild}, "pendulum", false, false, "", ""},
		{"hatch_build marker text not a requirement", map[string]string{"hatch_build.py": hatchBuild}, "python-version", false, false, "", ""},
		{"hatch_build docstring prose not a requirement", map[string]string{"hatch_build.py": hatchBuild}, "nothing", false, false, "", ""},
		{"requirements range carries constraint", map[string]string{"requirements.txt": requirements}, "flask", true, false, "", ">=2.0"},
		{"requirements exact pin has no constraint", map[string]string{"requirements.txt": requirements}, "requests", true, true, "2.31.0", ""},
		{"requirements parenthesized range", map[string]string{"requirements.txt": requirements}, "urllib3", true, false, "", ">=1.26"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, tt.files), tt.coord)
			if r.Found != tt.wantFound {
				t.Fatalf("Found = %v, want %v (all: %+v)", r.Found, tt.wantFound, r.All)
			}
			if !tt.wantFound {
				return
			}
			if r.Match.Resolved != tt.wantResolved || r.Match.Version != tt.wantVersion || r.Match.Constraint != tt.wantConstraint {
				t.Fatalf("Match = %+v, want resolved=%v version=%q constraint=%q", r.Match, tt.wantResolved, tt.wantVersion, tt.wantConstraint)
			}
		})
	}
}

// Exhaustive is claimed only against a complete, edge-bearing lockfile (uv/pdm/poetry) that
// covers every manifest found; every weaker shape fails open.
func TestResolveVersions_Exhaustive(t *testing.T) {
	const (
		uvLock = `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "flask" }, { name = "member" }]

[[package]]
name = "member"
version = "0.1.0"
source = { editable = "packages/member" }

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
		pdmLock = `[[package]]
name = "flask"
version = "3.0.0"
dependencies = ["jinja2>=3.1"]

[[package]]
name = "jinja2"
version = "3.1.4"
`
		poetryLock = `[[package]]
name = "flask"
version = "3.0.0"

[package.dependencies]
jinja2 = ">=3.1.2"

[[package]]
name = "jinja2"
version = "3.1.4"
`
		pyprojectCovered   = "[project]\nname = \"app\"\ndependencies = [\"flask>=3\", \"member\"]\n"
		pyprojectUncovered = "[project]\nname = \"app\"\ndependencies = [\"flask>=3\", \"aiohttp>=3.9\"]\n"
	)
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"uv.lock alone", map[string]string{"uv.lock": uvLock}, true},
		{"uv.lock covers pyproject incl. workspace member", map[string]string{"uv.lock": uvLock, "pyproject.toml": pyprojectCovered}, true},
		{"pdm.lock", map[string]string{"pdm.lock": pdmLock}, true},
		{"poetry.lock", map[string]string{"poetry.lock": poetryLock}, true},
		{"lock misses a declared name", map[string]string{"uv.lock": uvLock, "pyproject.toml": pyprojectUncovered}, false},
		{"pinned requirement disagrees with lock", map[string]string{"uv.lock": uvLock, "requirements.txt": "flask==2.0.0\n"}, false},
		{"requirements matching lock", map[string]string{"uv.lock": uvLock, "requirements.txt": "flask==3.0.0\njinja2==3.1.4\n"}, true},
		{"editable requirement", map[string]string{"uv.lock": uvLock, "requirements.txt": "-e .\nflask==3.0.0\n"}, false},
		{"manifest outside the lock's tree", map[string]string{"svc/uv.lock": uvLock, "requirements.txt": "flask==3.0.0\n"}, false},
		{"requirements only, fully pinned", map[string]string{"requirements.txt": "flask==3.0.0\njinja2==3.1.4\n"}, false},
		{"Pipfile.lock only", map[string]string{"Pipfile.lock": `{"default": {"flask": {"version": "==3.0.0"}}}`}, false},
		{"declared-only pyproject", map[string]string{"pyproject.toml": pyprojectCovered}, false},
		{"setup.py only", map[string]string{"setup.py": `setup(install_requires=["flask>=3"])`}, false},
		{"malformed poetry.lock", map[string]string{"poetry.lock": "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n[package.dependencies\n"}, false},
		{"malformed uv.lock", map[string]string{"uv.lock": "version = 1\n[[package]\nname = \"flask\"\n"}, false},
		{"malformed pyproject beside a lock", map[string]string{"uv.lock": uvLock, "pyproject.toml": "[project\nname = \"app\"\n"}, false},
		{"vcs requirement", map[string]string{"uv.lock": uvLock, "requirements.txt": "git+https://github.com/org/lib.git#egg=lib\nflask==3.0.0\n"}, false},
		{"url requirement", map[string]string{"uv.lock": uvLock, "requirements.txt": "https://example.com/lib-1.0.tar.gz\nflask==3.0.0\n"}, false},
		{"local sdist requirement", map[string]string{"uv.lock": uvLock, "requirements.txt": "./dist/lib-0.1.0.tar.gz\nflask==3.0.0\n"}, false},
		{"direct-reference requirement", map[string]string{"uv.lock": uvLock, "requirements.txt": "lib @ https://example.com/lib-1.0.tar.gz\nflask==3.0.0\n"}, false},
		{"pip-compile only, every line annotated", map[string]string{"requirements.txt": "flask==3.0.0\n    # via -r requirements.in\njinja2==3.1.4\n    # via flask\n"}, false},
		{"no manifest", map[string]string{"m.py": "x = 1\n"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, tt.files), "absent-package")
			if r.Found {
				t.Fatalf("absent-package unexpectedly found: %+v", r.Match)
			}
			if r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v (partiality %+v)", r.Exhaustive, tt.want, r.Partiality)
			}
		})
	}
}

// A lockfile omits the project itself, so an advisory naming a first-party project is never
// proven absent; a project name that cannot be read fails open for every coordinate.
func TestResolveVersions_ExhaustiveFirstParty(t *testing.T) {
	const uvLock = `version = 1
[[package]]
name = "my-app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "flask"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }
`
	const poetryLock = "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n"
	tests := []struct {
		name  string
		files map[string]string
		coord string
		want  bool
	}{
		{"uv root is first-party", map[string]string{"uv.lock": uvLock}, "my_app", false},
		{"uv lock, unrelated absent package", map[string]string{"uv.lock": uvLock}, "aiohttp", true},
		{"pyproject [project] name", map[string]string{"poetry.lock": poetryLock, "pyproject.toml": "[project]\nname = \"Svc.Core\"\n"}, "svc-core", false},
		{"pyproject [tool.poetry] name", map[string]string{"poetry.lock": poetryLock, "pyproject.toml": "[tool.poetry]\nname = \"svc\"\n"}, "svc", false},
		{"setup.cfg metadata name", map[string]string{"poetry.lock": poetryLock, "setup.cfg": "[metadata]\nname = svc\n"}, "svc", false},
		{"setup.py literal name", map[string]string{"poetry.lock": poetryLock, "setup.py": "setup(name=\"svc\", install_requires=[\"flask==3.0.0\"])\n"}, "svc", false},
		{"setup.py literal name, other package", map[string]string{"poetry.lock": poetryLock, "setup.py": "setup(name=\"svc\")\n"}, "aiohttp", true},
		{"setup.py computed name fails open", map[string]string{"poetry.lock": poetryLock, "setup.py": "Extension(name=\"svc._c\")\nsetup(name=NAME)\n"}, "aiohttp", false},
		{"setup.py shim with setup.cfg name", map[string]string{"poetry.lock": poetryLock, "setup.py": "setup()\n", "setup.cfg": "[metadata]\nname = svc\n"}, "aiohttp", true},
		{"poetry lexical read disagrees with TOML", map[string]string{"poetry.lock": "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n\n[[package]]\nname=\"jinja2\"\nversion=\"3.1.4\"\n"}, "aiohttp", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, tt.files), tt.coord)
			if r.Found {
				t.Fatalf("%s unexpectedly found", tt.coord)
			}
			if r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v", r.Exhaustive, tt.want)
			}
		})
	}
}

// A lockfile's dev/optional/group membership is never evidence of absence: a package locked only
// for development still resolves as present.
func TestResolveVersions_DevLockedPackagePresent(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
	}{
		{"uv dev-dependencies group", map[string]string{"uv.lock": `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
`}},
		{"poetry dev category", map[string]string{"poetry.lock": "[[package]]\nname = \"pytest\"\nversion = \"8.0.0\"\ncategory = \"dev\"\noptional = false\n"}},
		{"pdm dev group", map[string]string{"pdm.lock": "[[package]]\nname = \"pytest\"\nversion = \"8.0.0\"\ngroups = [\"dev\"]\n"}},
		{"poetry optional extra", map[string]string{"poetry.lock": "[[package]]\nname = \"pytest\"\nversion = \"8.0.0\"\noptional = true\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, tt.files), "pytest")
			if !r.Found || r.Match.Version != "8.0.0" {
				t.Fatalf("dev-locked pytest not reported present: found=%v match=%+v", r.Found, r.Match)
			}
		})
	}
}

// A "file:" directive in setup.cfg, and a [tool.setuptools.dynamic] or hatch-requirements-txt
// file list in pyproject.toml, are read as requirement lines relative to the manifest. A file
// that is missing, not local to the manifest's directory, or not plain requirements takes the
// parse-failure path: partiality tool_failure, so Exhaustive is withheld.
func TestResolveVersions_RequirementFileDirectives(t *testing.T) {
	const dynPyproject = "[project]\nname = \"app\"\ndynamic = [\"dependencies\", \"optional-dependencies\"]\n"
	tests := []struct {
		name           string
		files          map[string]string
		wantFound      bool
		wantConstraint string
		wantFailed     bool
	}{
		{"setup.cfg install_requires file:", map[string]string{
			"setup.cfg": "[options]\ninstall_requires = file: deps.txt\n",
			"deps.txt":  "# runtime\nflask>=3\npyjwt>=2.8  # tokens\n",
		}, true, ">=2.8", false},
		{"setup.cfg dangling file: list", map[string]string{
			"setup.cfg": "[options]\ninstall_requires =\n    file: base.txt,\n          extra.txt\n",
			"base.txt":  "flask>=3\n", "extra.txt": "pyjwt==2.8.0\n",
		}, true, "", false},
		{"setup.cfg extras_require file:", map[string]string{
			"setup.cfg": "[options.extras_require]\njwt = file: jwt.txt\n",
			"jwt.txt":   "pyjwt<3\n",
		}, true, "<3", false},
		{"setup.cfg file: in a subdirectory", map[string]string{
			"pkg/setup.cfg":     "[options]\ninstall_requires = file: reqs/deps.txt\n",
			"pkg/reqs/deps.txt": "pyjwt>=2\n",
		}, true, ">=2", false},
		{"setup.cfg file: missing", map[string]string{
			"setup.cfg": "[options]\ninstall_requires = file: deps.txt\n",
		}, false, "", true},
		{"setup.cfg file: escapes the project", map[string]string{
			"pkg/setup.cfg": "[options]\ninstall_requires = file: ../deps.txt\n",
			"deps.txt":      "pyjwt>=2\n",
		}, false, "", true},
		{"setup.cfg file: absolute", map[string]string{
			"setup.cfg":    "[options]\ninstall_requires = file: /etc/deps.txt\n",
			"etc/deps.txt": "pyjwt>=2\n",
		}, false, "", true},
		{"setup.cfg file: URL", map[string]string{
			"setup.cfg":                   "[options]\ninstall_requires = file: https://example.com/deps.txt\n",
			"https:/example.com/deps.txt": "pyjwt>=2\n",
		}, false, "", true},
		{"setup.cfg file: holding a pip include", map[string]string{
			"setup.cfg": "[options]\ninstall_requires = file: deps.txt\n",
			"deps.txt":  "-r more.txt\nflask>=3\n", "more.txt": "pyjwt\n",
		}, false, "", true},
		{"setup.cfg file: holding a non-requirement", map[string]string{
			"setup.cfg": "[options]\ninstall_requires = file: deps.txt\n",
			"deps.txt":  "flask>=3\n=broken\n",
		}, false, "", true},
		{"setup.cfg file: after a requirement", map[string]string{
			"setup.cfg": "[options]\ninstall_requires =\n    flask>=3\n    file: deps.txt\n",
			"deps.txt":  "pyjwt\n",
		}, false, "", true},
		{"pyproject setuptools dynamic dependencies", map[string]string{
			"pyproject.toml": dynPyproject + "[tool.setuptools.dynamic]\ndependencies = {file = [\"deps.txt\"]}\n",
			"deps.txt":       "pyjwt>=2.8\n",
		}, true, ">=2.8", false},
		{"pyproject setuptools dynamic optional group", map[string]string{
			"pyproject.toml": dynPyproject + "[tool.setuptools.dynamic.optional-dependencies]\njwt = {file = \"jwt.txt\"}\n",
			"jwt.txt":        "pyjwt<3\n",
		}, true, "<3", false},
		{"pyproject hatch requirements_txt", map[string]string{
			"pyproject.toml": dynPyproject + "[tool.hatch.metadata.hooks.requirements_txt]\nfiles = [\"deps.txt\"]\n[tool.hatch.metadata.hooks.requirements_txt.optional-dependencies]\njwt = [\"jwt.txt\"]\n",
			"deps.txt":       "flask>=3\n", "jwt.txt": "pyjwt>=2\n",
		}, true, ">=2", false},
		{"pyproject setuptools dynamic file missing", map[string]string{
			"pyproject.toml": dynPyproject + "[tool.setuptools.dynamic]\ndependencies = {file = [\"deps.txt\"]}\n",
		}, false, "", true},
		{"pyproject setuptools dynamic file escapes", map[string]string{
			"pkg/pyproject.toml": dynPyproject + "[tool.setuptools.dynamic]\ndependencies = {file = \"../deps.txt\"}\n",
			"deps.txt":           "pyjwt\n",
		}, false, "", true},
		{"pyproject setuptools dynamic unread shape", map[string]string{
			"pyproject.toml": dynPyproject + "[tool.setuptools.dynamic]\ndependencies = {attr = \"app.DEPS\"}\n",
		}, false, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, tt.files), "PyJWT")
			if r.Found != tt.wantFound {
				t.Fatalf("Found = %v, want %v (all: %+v)", r.Found, tt.wantFound, r.All)
			}
			if tt.wantFound && r.Match.Constraint != tt.wantConstraint {
				t.Fatalf("Constraint = %q, want %q", r.Match.Constraint, tt.wantConstraint)
			}
			failed := slices.Contains(r.Partiality.Reasons, plugin.PartialReasonToolFailure)
			if failed != tt.wantFailed {
				t.Fatalf("tool_failure = %v, want %v (partiality %+v)", failed, tt.wantFailed, r.Partiality)
			}
			if failed && r.Exhaustive {
				t.Fatal("Exhaustive despite a parse failure")
			}
		})
	}
}

// A symlinked "file:" target that resolves outside setup.cfg's directory is not local.
func TestResolveVersions_SetupCfgFileSymlinkEscape(t *testing.T) {
	outside := writeTree(t, map[string]string{"deps.txt": "pyjwt>=2\n"})
	root := writeTree(t, map[string]string{"setup.cfg": "[options]\ninstall_requires = file: deps.txt\n"})
	if err := os.Symlink(filepath.Join(outside, "deps.txt"), filepath.Join(root, "deps.txt")); err != nil {
		t.Fatal(err)
	}
	r := resolveVersion(t, root, "PyJWT")
	if r.Found || !slices.Contains(r.Partiality.Reasons, plugin.PartialReasonToolFailure) {
		t.Fatalf("symlink escape read: found=%v partiality=%+v", r.Found, r.Partiality)
	}
}
