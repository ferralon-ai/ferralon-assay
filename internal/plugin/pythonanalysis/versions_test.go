package pythonanalysis

import (
	"context"
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

// --- several pins of one project ---------------------------------------------

const resolveRuns = 50

func mustUnresolvedPy(t *testing.T, res plugin.DependencyVersionResult) {
	t.Helper()
	if !res.Found {
		t.Fatalf("coordinate not found; all=%+v", res.All)
	}
	if res.Match.Resolved || res.Match.Version != "" {
		t.Fatalf("match must be UNRESOLVED with no version; match=%+v", res.Match)
	}
}

// Two services in one repo lock different versions of one project: the predicate must not be
// handed whichever pin was read first.
func TestResolveVersions_ManifestsDisagreeUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"svc-a/requirements.txt": "Flask==2.2.0\n",
		"svc-b/poetry.lock":      "[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n",
	})
	for i := 0; i < resolveRuns; i++ {
		mustUnresolvedPy(t, resolveVersion(t, dir, "flask"))
	}
}

// poetry.lock carries one [[package]] block per marker-split version (numpy for old and new
// Pythons); either can be the installed one.
func TestResolveVersions_PoetryMarkerSplitUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"poetry.lock": `[[package]]
name = "numpy"
version = "1.24.4"

[[package]]
name = "numpy"
version = "1.26.4"
`,
	})
	mustUnresolvedPy(t, resolveVersion(t, dir, "numpy"))
}

func TestResolveVersions_PipfileDefaultDevelopDisagreeUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"Pipfile.lock": `{"default": {"urllib3": {"version": "==1.26.18"}}, "develop": {"urllib3": {"version": "==2.2.1"}}}`,
	})
	for i := 0; i < resolveRuns; i++ {
		mustUnresolvedPy(t, resolveVersion(t, dir, "urllib3"))
	}
}

func TestResolveVersions_SamePinAcrossManifestsResolves(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"requirements.txt": "Flask==2.3.0\n",
		"poetry.lock":      "[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n",
	})
	if r := resolveVersion(t, dir, "flask"); !r.Match.Resolved || r.Match.Version != "2.3.0" {
		t.Fatalf("one pin repeated across manifests want 2.3.0 resolved; got %+v", r.Match)
	}
}

// A declared range beside the lock's pin is the same environment, not a second copy: the pin
// still resolves (the npm unknown-copy veto deliberately does not apply here).
func TestResolveVersions_DeclaredRangeBesideLockPinResolves(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pyproject.toml": "[project]\nname = \"app\"\ndependencies = [\n    \"flask>=2.0\",\n]\n",
		"poetry.lock":    "[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n",
	})
	if r := resolveVersion(t, dir, "flask"); !r.Match.Resolved || r.Match.Version != "2.3.0" {
		t.Fatalf("range declaration + lock pin want 2.3.0 resolved; got %+v", r.Match)
	}
}

// An unpinned requirement in one service can install any version, whatever another service
// pins: the pin must not stand in for it.
func TestResolveVersions_UnpinnedServiceBesidePinnedServiceUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"service-a/requirements.txt": "requests==2.32.3\n",
		"service-b/requirements.txt": "requests>=2.0\n",
	})
	for i := 0; i < resolveRuns; i++ {
		mustUnresolvedPy(t, resolveVersion(t, dir, "requests"))
	}
}

// A pyproject range is covered only by the lock in its own project directory, not by a lock
// elsewhere in the repo.
func TestResolveVersions_RangeBesideOtherProjectsLockUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"svc-a/poetry.lock":    "[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n",
		"svc-b/pyproject.toml": "[project]\nname = \"b\"\ndependencies = [\n    \"flask>=2.0\",\n]\n",
	})
	for i := 0; i < resolveRuns; i++ {
		mustUnresolvedPy(t, resolveVersion(t, dir, "flask"))
	}
}

// A manifest that fails to parse may hold another copy, so the readable pin cannot decide.
func TestResolveVersions_CorruptSecondLockUnresolved(t *testing.T) {
	for lock, body := range map[string]string{
		"Pipfile.lock": `{"default": {"flask": {"version": "==2.`,
		"uv.lock":      "version = 1\n[[package]\nname = \"flask\"\n",
	} {
		t.Run(lock, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/" + lock:          body,
			})
			for i := 0; i < resolveRuns; i++ {
				res := resolveVersion(t, dir, "flask")
				mustUnresolvedPy(t, res)
				if res.Partiality.Complete {
					t.Fatalf("a corrupt %s must leave the result partial", lock)
				}
			}
			if resolveVersion(t, dir, "requests").Found {
				t.Fatal("a coordinate no readable manifest holds must stay not found")
			}
		})
	}
}

// pipenv locks the Pipfile, not [project].dependencies, so a Pipfile.lock pin does not
// resolve a pyproject range in the same directory.
func TestResolveVersions_PyprojectRangeBesidePipfileLockUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pyproject.toml": "[project]\nname = \"a\"\ndependencies = [\n    \"flask>=2.0\",\n]\n",
		"Pipfile.lock":   `{"default": {"flask": {"version": "==2.3.0"}}}`,
	})
	for i := 0; i < resolveRuns; i++ {
		mustUnresolvedPy(t, resolveVersion(t, dir, "flask"))
	}
}

// A URL or VCS requirement installs a copy whose version is unreadable here, so it vetoes
// a pin for the same project in another manifest.
func TestResolveVersions_URLRequirementVetoesPin(t *testing.T) {
	for name, req := range map[string]string{
		"pep508":        "requests @ https://example.com/requests-2.31.0.tar.gz\n",
		"pep508-extras": "requests[socks] @ https://example.com/requests-2.31.0.tar.gz\n",
		"vcs-egg":       "git+https://github.com/psf/requests.git@v2.31.0#egg=requests\n",
		"editable-vcs":  "-e git+https://github.com/psf/requests.git#egg=requests\n",
		"url-egg":       "https://example.com/requests-2.31.0.tar.gz#egg=requests\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "requests==2.32.3\n",
				"svc-b/requirements.txt": req,
			})
			for i := 0; i < resolveRuns; i++ {
				mustUnresolvedPy(t, resolveVersion(t, dir, "requests"))
			}
		})
	}
}

// A URL or VCS requirement that names no project can install the advisory's package at any
// version, so it leaves every found coordinate unresolved, like a parse failure.
func TestResolveVersions_NamelessURLRequirementUnresolved(t *testing.T) {
	for name, req := range map[string]string{
		"archive":      "https://example.com/dist/pkg-1.0.tar.gz\n",
		"vcs":          "git+https://github.com/example/pkg.git@v1.0\n",
		"editable-vcs": "-e git+https://github.com/example/pkg.git\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/requirements.txt": req,
			})
			for i := 0; i < resolveRuns; i++ {
				res := resolveVersion(t, dir, "flask")
				mustUnresolvedPy(t, res)
				if res.Partiality.Complete {
					t.Fatal("a nameless URL requirement must leave the result partial")
				}
			}
			if resolveVersion(t, dir, "requests").Found {
				t.Fatal("a coordinate no manifest names must stay not found")
			}
		})
	}
}

// The same veto holds for a PEP 508 direct reference in pyproject.toml.
func TestResolveVersions_PyprojectURLDependencyVetoesPin(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"svc-a/requirements.txt": "requests==2.32.3\n",
		"svc-b/pyproject.toml":   "[project]\nname = \"b\"\ndependencies = [\n    \"requests @ https://example.com/requests-2.31.0.tar.gz\",\n]\n",
	})
	for i := 0; i < resolveRuns; i++ {
		mustUnresolvedPy(t, resolveVersion(t, dir, "requests"))
	}
}

// Option lines that carry a URL are not requirements and name no project.
func TestResolveVersions_IndexURLOptionIgnored(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"requirements.txt": "--index-url https://pypi.example.com/simple\n--extra-index-url https://x.example.com/simple\n-e .\nrequests==2.32.3\n",
	})
	res := resolveVersion(t, dir, "requests")
	if !res.Found || !res.Match.Resolved || res.Match.Version != "2.32.3" {
		t.Fatalf("got %+v", res.Match)
	}
	if len(res.All) != 1 {
		t.Fatalf("All = %+v, want only requests", res.All)
	}
}

// A Pipfile is not read, so one with packages vetoes another service's pin.
func TestResolveVersions_PipfileRangeWithoutLockVetoesPin(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"svc-a/requirements.txt": "flask==2.3.0\n",
		"svc-b/Pipfile":          "[packages]\nflask = \">=2.0\"\n",
	})
	mustVetoedPy(t, dir, "flask")
}

// A Pipfile vetoes even beside its own Pipfile.lock: pipenv re-locks a stale lock, so the
// lock is not proof of what the Pipfile installs.
func TestResolveVersions_PipfileBesideOwnLockVetoes(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"Pipfile":      "[packages]\nflask = \">=2.0\"\n\n[dev-packages]\npytest = \"*\"\n",
		"Pipfile.lock": `{"default": {"flask": {"version": "==2.3.0"}}, "develop": {"pytest": {"version": "==8.0.0"}}}`,
	})
	mustVetoedPy(t, dir, "flask")
	mustVetoedPy(t, dir, "pytest")
}

// [tool.poetry] dependencies are not read, so they veto even beside their own poetry.lock,
// group dependencies included.
func TestResolveVersions_PoetryBesideOwnLockVetoes(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pyproject.toml": "[tool.poetry]\nname = \"app\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\nflask = \"^2.0\"\n\n[tool.poetry.group.dev.dependencies]\npytest = {version = \">=8\"}\n",
		"poetry.lock":    "[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n\n[[package]]\nname = \"pytest\"\nversion = \"8.0.0\"\n",
	})
	mustVetoedPy(t, dir, "flask")
	mustVetoedPy(t, dir, "pytest")
}

// [tool.poetry] main, dev and group dependencies each veto another service's pin.
func TestResolveVersions_PoetryRangeWithoutLockVetoesPin(t *testing.T) {
	for name, table := range map[string]string{
		"main":  "[tool.poetry.dependencies]\nflask = \"^2.0\"\n",
		"dev":   "[tool.poetry.dev-dependencies]\npytest = \"^8\"\n",
		"group": "[tool.poetry.group.web.dependencies]\nflask = {version = \"^2.0\"}\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/pyproject.toml":   "[tool.poetry]\nname = \"b\"\n\n" + table,
			})
			mustVetoedPy(t, dir, "flask")
		})
	}
}

// An exact Pipfile or Poetry pin is not read either: equal to another service's pin, it
// still vetoes.
func TestResolveVersions_DeclaredExactPins(t *testing.T) {
	for name, file := range map[string]string{
		"Pipfile":        "[packages]\nflask = \"==2.3.0\"\n",
		"pyproject.toml": "[tool.poetry.dependencies]\nflask = \"2.3.0\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/" + name:          file,
			})
			mustVetoedPy(t, dir, "flask")
		})
	}
}

// A Pipfile with no package category, and a [tool.poetry] that declares only the
// interpreter, install nothing and do not veto.
func TestResolveVersions_DeclarationsWithoutPackagesDoNotVeto(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"svc-a/requirements.txt": "flask==2.3.0\n",
		"svc-b/Pipfile":          "[[source]]\nurl = \"https://pypi.org/simple\"\nname = \"pypi\"\n\n[requires]\npython_version = \"3.11\"\n\n[packages]\n",
		"svc-c/pyproject.toml":   "[tool.poetry]\nname = \"c\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\n\n[tool.poetry.group.dev.dependencies]\n",
	})
	mustResolvedCompletePy(t, dir, "flask", "2.3.0")
}

// mustVetoedPy asserts the parse-failure outcome: the found coordinate is unresolved, the
// result is partial, and a coordinate no manifest names stays not found.
func mustVetoedPy(t *testing.T, dir, coordinate string) {
	t.Helper()
	for i := 0; i < resolveRuns; i++ {
		res := resolveVersion(t, dir, coordinate)
		mustUnresolvedPy(t, res)
		if res.Partiality.Complete {
			t.Fatal("result must be partial")
		}
	}
	if resolveVersion(t, dir, "no-such-project").Found {
		t.Fatal("a coordinate no manifest names must stay not found")
	}
}

// mustResolvedCompletePy asserts the coordinate resolves to want and the result is complete.
func mustResolvedCompletePy(t *testing.T, dir, coordinate, want string) {
	t.Helper()
	for i := 0; i < resolveRuns; i++ {
		res := resolveVersion(t, dir, coordinate)
		if !res.Match.Resolved || res.Match.Version != want || !res.Partiality.Complete {
			t.Fatalf("want %s resolved and complete; got %+v %+v", want, res.Match, res.Partiality)
		}
	}
}

// A -r or -c include is not followed, so it vetoes whatever the included file is called
// and whatever it holds.
func TestResolveVersions_IncludeFollowedWhateverItsName(t *testing.T) {
	for name, tc := range map[string]struct{ line, file, body string }{
		"r-space":         {"-r deps/common.in\n", "deps/common.in", "flask>=2.0\n"},
		"r-glued":         {"-rbase.txt\n", "base.txt", "flask>=2.0\n"},
		"requirement-eq":  {"--requirement=../shared/base.pip\n", "../shared/base.pip", "flask>=2.0\n"},
		"c-space":         {"-c constraints.txt\n", "constraints.txt", "flask==2.3.0\n"},
		"constraint-long": {"--constraint pins/all.txt\n", "pins/all.txt", "flask==2.3.0\n"},
		"nested":          {"-r a.in\n", "a.in", "-r b.in\n"},
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/requirements.txt": "requests==2.32.3\n" + tc.line,
				"svc-b/" + tc.file:       tc.body,
			}
			if name == "nested" {
				files["svc-b/b.in"] = "flask==2.3.0\n"
			}
			dir := writeTree(t, files)
			mustVetoedPy(t, dir, "flask")
			mustVetoedPy(t, dir, "requests")
		})
	}
}

// Includes that loop back veto like any other include, and resolution terminates.
func TestResolveVersions_IncludeCycleTerminates(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"requirements.txt": "-r base.in\nflask==2.3.0\n",
		"base.in":          "-r requirements.txt\n-r base.in\nrequests==2.32.3\n",
	})
	mustVetoedPy(t, dir, "flask")
}

// An include that is a URL vetoes.
func TestResolveVersions_URLIncludeUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"svc-a/requirements.txt": "flask==2.3.0\n",
		"svc-b/requirements.txt": "-r https://example.com/requirements.txt\n",
	})
	mustVetoedPy(t, dir, "flask")
}

// A local include that is missing, a directory, or outside the build directory vetoes.
func TestResolveVersions_UnreadableIncludeUnresolved(t *testing.T) {
	for name, tc := range map[string]struct {
		line  string
		extra map[string]string
	}{
		"missing":   {"-r missing.txt\n", nil},
		"directory": {"-c deps\n", map[string]string{"build/svc-b/deps/x.txt": "flask==2.3.0\n"}},
		"outside":   {"-r ../../outside.txt\n", map[string]string{"outside.txt": "flask==2.3.0\n"}},
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{
				"build/svc-a/requirements.txt": "flask==2.3.0\n",
				"build/svc-b/requirements.txt": tc.line,
			}
			for k, v := range tc.extra {
				files[k] = v
			}
			mustVetoedPy(t, filepath.Join(writeTree(t, files), "build"), "flask")
		})
	}
}

// A local path or file: install other than the project itself can be any distribution at
// any version, so it takes the parse-failure path.
func TestResolveVersions_LocalPathInstallVetoes(t *testing.T) {
	for name, req := range map[string]string{
		"editable-vendor": "-e ./vendor/x\n",
		"editable-eq":     "--editable=../lib\n",
		"editable-bare":   "-e lib/x\n",
		"wheel":           "./dist/x-1.0-py3-none-any.whl\n",
		"sdist-name":      "x-1.0.tar.gz\n",
		"file-url":        "file:../wheels/x-1.0-py3-none-any.whl\n",
		"file-url-egg":    "file:///opt/src/x#egg=x\n",
		"pep508-file":     "x @ file:///opt/src/x\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/requirements.txt": req,
			})
			mustVetoedPy(t, dir, "flask")
		})
	}
}

// Installing the project's own directory does not veto: "-e .", ".", extras, or a path
// that resolves to the requirements file's directory.
func TestResolveVersions_ProjectSelfInstallDoesNotVeto(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"svc/requirements.txt": "-e .\n.\n-e .[dev]\n./\n-e ../svc\nflask==2.3.0\n",
	})
	mustResolvedCompletePy(t, dir, "flask", "2.3.0")
}

// Pipfile and Poetry path dependencies veto, the project's own path included, because
// neither file is read. A [project] file: dependency on another directory vetoes; one on
// the project's own directory does not.
func TestResolveVersions_DeclaredLocalPathVetoes(t *testing.T) {
	for name, tc := range map[string]struct{ file, body string }{
		"Pipfile":      {"Pipfile", "[packages]\nx = {path = \"./vendor/x\", editable = true}\n"},
		"Pipfile-self": {"Pipfile", "[packages]\napp = {path = \".\", editable = true}\n"},
		"poetry":       {"pyproject.toml", "[tool.poetry.dependencies]\nx = {path = \"../lib/x\"}\n"},
		"project-file": {"pyproject.toml", "[project]\nname = \"b\"\ndependencies = [\"x @ file:../lib/x\"]\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/" + tc.file:       tc.body,
			})
			mustVetoedPy(t, dir, "flask")
		})
	}
	self := writeTree(t, map[string]string{
		"svc-a/requirements.txt": "flask==2.3.0\n",
		"svc-b/pyproject.toml":   "[project]\nname = \"b\"\ndependencies = [\"b @ file:.\"]\n",
	})
	mustResolvedCompletePy(t, self, "flask", "2.3.0")
}

// setup.py and setup.cfg that declare install_requires or extras_require, and a
// hatch_build.py hook that sets dependencies, are not read, so they veto.
func TestResolveVersions_SetupDeclarationsVeto(t *testing.T) {
	for name, tc := range map[string]struct{ file, body string }{
		"setup.py-install": {"setup.py", "from setuptools import setup\nsetup(name=\"b\", install_requires=[\"flask>=2\"])\n"},
		"setup.py-extras":  {"setup.py", "from setuptools import setup\nsetup(name=\"b\", extras_require={\"web\": [\"flask\"]})\n"},
		"setup.cfg":        {"setup.cfg", "[metadata]\nname = b\n\n[options]\ninstall_requires =\n    flask>=2\n"},
		"hatch_build.py":   {"hatch_build.py", "from hatchling.metadata.plugin.interface import MetadataHookInterface\nclass H(MetadataHookInterface):\n    def update(self, metadata):\n        metadata[\"dependencies\"] = [\"flask\"]\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/" + tc.file:       tc.body,
			})
			mustVetoedPy(t, dir, "flask")
		})
	}
}

// setup files that declare no dependencies do not veto.
func TestResolveVersions_SetupWithoutDeclarationsDoesNotVeto(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"svc-a/requirements.txt": "flask==2.3.0\n",
		"svc-b/setup.py":         "from setuptools import setup\nsetup(name=\"b\")\n",
		"svc-b/setup.cfg":        "[metadata]\nname = b\n",
		"svc-b/hatch_build.py":   "from hatchling.builders.hooks.plugin.interface import BuildHookInterface\nclass H(BuildHookInterface):\n    pass\n",
	})
	mustResolvedCompletePy(t, dir, "flask", "2.3.0")
}

// A conda environment that installs a conda package or has a pip: section is not read, so
// it vetoes.
func TestResolveVersions_CondaEnvironmentVetoes(t *testing.T) {
	for name, tc := range map[string]struct{ file, body string }{
		"conda-package": {"environment.yml", "name: b\ndependencies:\n  - python=3.11\n  - conda-forge::flask>=2\n"},
		"pip-section":   {"environment.yaml", "name: b\ndependencies:\n  - python=3.11\n  - pip\n  - pip:\n    - flask==2.3.0\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/" + tc.file:       tc.body,
			})
			mustVetoedPy(t, dir, "flask")
		})
	}
}

// A conda environment that installs only the interpreter and pip does not veto.
func TestResolveVersions_CondaInterpreterOnlyDoesNotVeto(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"svc-a/requirements.txt": "flask==2.3.0\n",
		"svc-b/environment.yml":  "name: b\nchannels:\n  - conda-forge\ndependencies:\n  - python>=3.11\n  - conda-forge::pip\n",
	})
	mustResolvedCompletePy(t, dir, "flask", "2.3.0")
}

// A requirements file whose name does not start with "requirements", any .txt under a
// requirements/ directory, and a pip-tools .in source are not read, so they veto, even when
// the .in sits beside the .txt compiled from it.
func TestResolveVersions_NonStandardRequirementsNameVetoes(t *testing.T) {
	for name, file := range map[string]string{
		"dev-prefix":       "dev-requirements.txt",
		"underscore":       "test_requirements.txt",
		"requirements-dir": "requirements/prod.txt",
		"in-source":        "requirements.in",
		"in-under-dir":     "requirements/base.in",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/" + file:          "flask>=2.0\n",
			})
			mustVetoedPy(t, dir, "flask")
		})
	}
	beside := writeTree(t, map[string]string{
		"requirements.in":  "flask>=2.0\n",
		"requirements.txt": "flask==2.3.0\n",
	})
	mustVetoedPy(t, beside, "flask")
}

// A requirements-*.txt name is read, and a .txt elsewhere that neither is named nor reads as
// a requirements file is ignored.
func TestResolveVersions_StandardRequirementsNamesRead(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"requirements-dev.txt": "flask==2.3.0\n",
		"docs/notes.txt":       "Install flask 2.0 or later.\n",
		"LICENSE.txt":          "MIT\n",
	})
	mustResolvedCompletePy(t, dir, "flask", "2.3.0")
}

// pyproject.toml tables other than [project].dependencies are not read, so each vetoes,
// even beside a lock that pins the coordinate.
func TestResolveVersions_PyprojectUnreadTablesVeto(t *testing.T) {
	for name, table := range map[string]string{
		"optional-dependencies": "[project]\nname = \"b\"\n\n[project.optional-dependencies]\nweb = [\"flask>=2\"]\n",
		"dependency-groups":     "[project]\nname = \"b\"\n\n[dependency-groups]\ndev = [\"flask>=2\", {include-group = \"x\"}]\n",
		"uv-dev":                "[project]\nname = \"b\"\n\n[tool.uv]\ndev-dependencies = [\"flask>=2\"]\n",
		"pdm-dev":               "[project]\nname = \"b\"\n\n[tool.pdm.dev-dependencies]\ntest = [\"flask>=2\"]\n",
		"dynamic-deps":          "[project]\nname = \"b\"\ndynamic = [\"version\", \"dependencies\"]\n\n[tool.setuptools.dynamic]\ndependencies = {file = [\"deps.txt\"]}\n",
		"dynamic-optional":      "[project]\nname = \"b\"\ndynamic = [\"optional-dependencies\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/pyproject.toml":   table,
				"svc-b/uv.lock":          "version = 1\n\n[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n",
			})
			mustVetoedPy(t, dir, "flask")
		})
	}
}

// [project].dependencies is read, and a dynamic field that is not a dependency list does
// not veto.
func TestResolveVersions_PyprojectReadTablesDoNotVeto(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pyproject.toml": "[project]\nname = \"a\"\ndynamic = [\"version\"]\ndependencies = [\"flask==2.3.0\"]\n\n[project.optional-dependencies]\n\n[tool.uv]\ndev-dependencies = []\n",
	})
	mustResolvedCompletePy(t, dir, "flask", "2.3.0")
}

// A same-directory lock covers a [project] range only when its pin satisfies the range;
// a pin outside it is a stale lock, so the range still vetoes.
func TestResolveVersions_StaleLockDoesNotCoverRange(t *testing.T) {
	for lock, body := range map[string]string{
		"uv.lock":     "version = 1\n\n[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n",
		"pdm.lock":    "[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n",
		"poetry.lock": "[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n",
	} {
		t.Run(lock, func(t *testing.T) {
			stale := writeTree(t, map[string]string{
				"pyproject.toml": "[project]\nname = \"a\"\ndependencies = [\"flask>=2.0,<2.3\"]\n",
				lock:             body,
			})
			for i := 0; i < resolveRuns; i++ {
				mustUnresolvedPy(t, resolveVersion(t, stale, "flask"))
			}
			fresh := writeTree(t, map[string]string{
				"pyproject.toml": "[project]\nname = \"a\"\ndependencies = [\"Flask[async] (>=2.0,<3) ; python_version >= '3.8'\"]\n",
				lock:             body,
			})
			mustResolvedCompletePy(t, fresh, "flask", "2.3.0")
		})
	}
}

// A [project] direct reference is never covered by a lock beside it.
func TestResolveVersions_DirectReferenceBesideOwnLockUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pyproject.toml": "[project]\nname = \"a\"\ndependencies = [\"flask @ https://example.com/flask-2.3.0.tar.gz\"]\n",
		"uv.lock":        "version = 1\n\n[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n",
	})
	for i := 0; i < resolveRuns; i++ {
		mustUnresolvedPy(t, resolveVersion(t, dir, "flask"))
	}
}

// Pipfile.lock's maps are walked in sorted key order, so All is the same on every run.
func TestResolveVersions_PipfileAllOrderDeterministic(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"Pipfile.lock": `{"default": {"requests": {"version": "==2.31.0"}, "flask": {"version": "==2.3.0"}, "idna": {"version": "==3.6"}},
"develop": {"pytest": {"version": "==8.1.0"}, "black": {"version": "==24.2.0"}}}`,
	})
	want := []string{"flask", "idna", "requests", "black", "pytest"}
	for i := 0; i < resolveRuns; i++ {
		var got []string
		for _, d := range resolveVersion(t, dir, "flask").All {
			got = append(got, d.Coordinate)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d: All order = %v, want %v", i, got, want)
		}
	}
}
