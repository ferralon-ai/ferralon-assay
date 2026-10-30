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

// [tool.poetry] dependencies, group dependencies included, are covered by their own
// poetry.lock when its pin satisfies the translated constraint.
func TestResolveVersions_PoetryBesideOwnLockResolves(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pyproject.toml": "[tool.poetry]\nname = \"app\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\nflask = \"^2.0\"\n\n[tool.poetry.group.dev.dependencies]\npytest = {version = \">=8\"}\n",
		"poetry.lock":    "[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n\n[[package]]\nname = \"pytest\"\nversion = \"8.0.0\"\n",
	})
	mustResolvedCompletePy(t, dir, "flask", "2.3.0")
	mustResolvedCompletePy(t, dir, "pytest", "8.0.0")
}

// mustUndecidedCompletePy asserts the coordinate is found but unresolved while the result stays
// complete: a declared range no lock covers, not an unread surface.
func mustUndecidedCompletePy(t *testing.T, dir, coordinate string) {
	t.Helper()
	for i := 0; i < resolveRuns; i++ {
		res := resolveVersion(t, dir, coordinate)
		mustUnresolvedPy(t, res)
		if !res.Partiality.Complete {
			t.Fatalf("result must stay complete; got %+v", res.Partiality)
		}
	}
}

// A [tool.poetry] main, dev or group range no lock covers leaves another service's pin
// unresolved without making the result partial.
func TestResolveVersions_PoetryRangeWithoutLockLeavesPinUnresolved(t *testing.T) {
	for name, table := range map[string]string{
		"main":  "[tool.poetry.dependencies]\nflask = \"^2.0\"\n",
		"dev":   "[tool.poetry.dev-dependencies]\nflask = \"^2\"\n",
		"group": "[tool.poetry.group.web.dependencies]\nflask = {version = \"^2.0\"}\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"svc-a/requirements.txt": "flask==2.3.0\n",
				"svc-b/pyproject.toml":   "[tool.poetry]\nname = \"b\"\n\n" + table,
			})
			mustUndecidedCompletePy(t, dir, "flask")
		})
	}
}

// An exact Pipfile pin is not read: equal to another service's pin, it still vetoes. An exact
// Poetry pin is read, so the two agree.
func TestResolveVersions_DeclaredExactPins(t *testing.T) {
	pin := "svc-a/requirements.txt"
	mustVetoedPy(t, writeTree(t, map[string]string{pin: "flask==2.3.0\n", "svc-b/Pipfile": "[packages]\nflask = \"==2.3.0\"\n"}), "flask")
	mustResolvedCompletePy(t, writeTree(t, map[string]string{pin: "flask==2.3.0\n", "svc-b/pyproject.toml": "[tool.poetry.dependencies]\nflask = \"2.3.0\"\n"}), "flask", "2.3.0")
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

// Matches lists the lock entries and installed copies of the package, and MatchesComplete holds
// only when complete lockfiles govern every manifest and every surface was read: a declaration a
// lock does not pin, or a manifest no lock governs, may install a version no reader saw.
func TestResolveVersions_MatchesComplete(t *testing.T) {
	const (
		lock300      = "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n"
		lock233      = "[[package]]\nname = \"flask\"\nversion = \"2.3.3\"\n"
		lock232      = "[[package]]\nname = \"flask\"\nversion = \"2.3.2\"\n"
		uvNoFlask    = "version = 1\n[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
		metadata200  = "Metadata-Version: 2.1\nName: Flask\nVersion: 2.0.0\n"
		sitePackages = ".venv/lib/python3.12/site-packages/"
	)
	tests := []struct {
		name     string
		files    map[string]string
		versions []string
		complete bool
	}{
		{"one lock per service", map[string]string{"poetry.lock": lock300, "svc/poetry.lock": lock233}, []string{"3.0.0", "2.3.3"}, true},
		{"a pyproject its lock pins", map[string]string{"poetry.lock": lock300, "pyproject.toml": "[project]\nname = \"app\"\ndependencies = [\"flask>=3\"]\n"}, []string{"3.0.0"}, true},
		{"an installed copy joins the set", map[string]string{"poetry.lock": lock300, sitePackages + "flask-2.0.0.dist-info/METADATA": metadata200}, []string{"3.0.0", "2.0.0"}, true},
		{"requirements pins with no lock", map[string]string{"requirements.txt": "flask==2.3.2\n"}, nil, false},
		{"an unlocked service beside a locked one", map[string]string{"poetry.lock": lock300, "svc/requirements.txt": "requests==2.31.0\n"}, []string{"3.0.0"}, false},
		{"a pyproject pin its uv.lock omits", map[string]string{"pyproject.toml": "[project]\nname = \"app\"\ndependencies = [\"flask==2.3.1\"]\n", "uv.lock": uvNoFlask}, nil, false},
		{"a pyproject pin its poetry.lock contradicts", map[string]string{"pyproject.toml": "[project]\nname = \"app\"\ndependencies = [\"flask==2.3.1\"]\n", "poetry.lock": lock232}, []string{"2.3.2"}, false},
		{"setup.py declarations", map[string]string{"poetry.lock": lock300, "svc/setup.py": "from setuptools import setup\nsetup(name=\"svc\", install_requires=[\"flask==2.0.1\"])\n"}, []string{"3.0.0"}, false},
		{"a wheel named for the package", map[string]string{"poetry.lock": lock300, "dist/flask-2.0.0-py3-none-any.whl": "PK"}, []string{"3.0.0"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, tc.files), "Flask")
			var got []string
			for _, m := range r.Matches {
				got = append(got, m.Version)
			}
			if tc.versions != nil && !slices.Equal(got, tc.versions) {
				t.Errorf("Matches versions = %q, want %q", got, tc.versions)
			}
			if r.MatchesComplete != tc.complete {
				t.Errorf("MatchesComplete = %v, want %v (Matches %+v)", r.MatchesComplete, tc.complete, r.Matches)
			}
		})
	}
}

// An installed copy whose metadata cannot be read leaves the set incomplete.
func TestResolveVersions_MatchesCompleteUnreadableCopy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0 file")
	}
	meta := ".venv/lib/python3.12/site-packages/flask-2.0.0.dist-info/METADATA"
	dir := writeTree(t, map[string]string{
		"poetry.lock": "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n",
		meta:          "Metadata-Version: 2.1\nName: Flask\nVersion: 2.0.0\n",
	})
	if err := os.Chmod(filepath.Join(dir, meta), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, meta), 0o644) })
	if r := resolveVersion(t, dir, "flask"); r.MatchesComplete {
		t.Fatalf("MatchesComplete with an unreadable installed copy: %+v", r.Matches)
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
		{"setup.py tests_require read", map[string]string{"setup.py": setupPy}, "nose", true, false, "", ">=1"},
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
		{"requirements matching lock", map[string]string{"uv.lock": uvLock, "requirements.txt": "flask==3.0.0\njinja2==3.1.4\n"}, false},
		{"requirements matching lock, hashed", map[string]string{"uv.lock": uvLock, "requirements.txt": "flask==3.0.0 --hash=sha256:aaa\njinja2==3.1.4 --hash=sha256:aaa\n"}, true},
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

// A setup.py whose declarations are computed rather than literal, and a hatch_build.py hook
// that sets dependencies, cannot be read completely, so they veto.
func TestResolveVersions_SetupDeclarationsVeto(t *testing.T) {
	for name, tc := range map[string]struct{ file, body string }{
		"setup.py-computed": {"setup.py", "from setuptools import setup\nREQS = open(\"r.txt\").read().split()\nsetup(name=\"b\", install_requires=REQS)\n"},
		"hatch_build.py":    {"hatch_build.py", "from hatchling.metadata.plugin.interface import MetadataHookInterface\nclass H(MetadataHookInterface):\n    def update(self, metadata):\n        metadata[\"dependencies\"] = [\"flask\"]\n"},
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

// Dynamic dependencies whose file is missing or that name no file veto, even beside a lock
// that pins the coordinate; so does a dependency group or tool table holding an entry nothing
// here can read: an installer rejects the malformed group shapes, and a local path or
// untranslatable poetry constraint installs a version nothing here reads.
func TestResolveVersions_PyprojectUnreadTablesVeto(t *testing.T) {
	const head = "[project]\nname = \"b\"\n\n"
	for name, table := range map[string]string{
		"dynamic-deps":              head[:len(head)-1] + "dynamic = [\"version\", \"dependencies\"]\n\n[tool.setuptools.dynamic]\ndependencies = {file = [\"deps.txt\"]}\n",
		"dynamic-optional":          head[:len(head)-1] + "dynamic = [\"optional-dependencies\"]\n",
		"group-include-unknown":     head + "[dependency-groups]\ndev = [\"flask>=2\", {include-group = \"x\"}]\n",
		"group-include-cycle":       head + "[dependency-groups]\ndev = [\"flask>=2\", {include-group = \"test\"}]\ntest = [{include-group = \"dev\"}]\n",
		"group-include-self":        head + "[dependency-groups]\ndev = [\"flask>=2\", {include-group = \"dev\"}]\n",
		"group-include-extra-key":   head + "[dependency-groups]\ndev = [\"flask>=2\", {include-group = \"test\", optional = true}]\ntest = []\n",
		"group-include-not-string":  head + "[dependency-groups]\ndev = [\"flask>=2\", {include-group = 1}]\n\"\" = []\n",
		"group-entry-not-string":    head + "[dependency-groups]\ndev = [\"flask>=2\", 1]\n",
		"group-not-array":           head + "[dependency-groups]\ndev = \"flask>=2\"\n",
		"group-names-collide":       head + "[dependency-groups]\nDev_Tools = [\"flask>=2\"]\ndev-tools = []\n",
		"group-entry-unparseable":   head + "[dependency-groups]\ndev = [\"flask>=2\", \"=bad\"]\n",
		"group-entry-local-file":    head + "[dependency-groups]\ndev = [\"flask>=2\", \"lib @ file:///opt/lib\"]\n",
		"uv-dev-not-string":         head + "[tool.uv]\ndev-dependencies = [\"flask>=2\", {name = \"x\"}]\n",
		"pdm-dev-editable":          head + "[tool.pdm.dev-dependencies]\ntest = [\"flask>=2\", \"-e ./lib\"]\n",
		"pdm-dev-not-array":         head + "[tool.pdm.dev-dependencies]\ntest = \"flask>=2\"\n",
		"hatch-dep-not-string":      head + "[tool.hatch.envs.default]\ndependencies = [\"flask>=2\", 1]\n",
		"hatch-extra-not-string":    head + "[tool.hatch.envs.test]\nextra-dependencies = [\"flask>=2\", {name = \"x\"}]\n",
		"hatch-dep-not-array":       head + "[tool.hatch.envs.default]\ndependencies = \"flask>=2\"\n",
		"hatch-dep-unparseable":     head + "[tool.hatch.envs.default]\ndependencies = [\"flask>=2\", \"=bad\"]\n",
		"hatch-dep-local-file":      head + "[tool.hatch.envs.default]\ndependencies = [\"lib @ file:///opt/lib\"]\n",
		"hatch-matrix-override":     head + "[tool.hatch.envs.test]\ndependencies = [\"pytest\"]\n\n[[tool.hatch.envs.test.matrix]]\nflask = [\"1\", \"2\"]\n\n[tool.hatch.envs.test.overrides]\nmatrix.flask.dependencies = [{value = \"flask<2\", if = [\"1\"]}]\n",
		"hatch-env-override":        head + "[tool.hatch.envs.test.overrides]\nenv.CI.extra-dependencies = [\"flask<2\"]\n",
		"hatch-post-install-pip":    head + "[tool.hatch.envs.default]\npost-install-commands = [\"pip install 'flask<2'\"]\n",
		"hatch-pre-install-chained": head + "[tool.hatch.envs.default]\npre-install-commands = [\"echo hi && python -m pip install flask<2\"]\n",
		"hatch-script-string":       head + "[tool.hatch.envs.default.scripts]\nsetup = \"uv pip install 'flask<2'\"\n",
		"hatch-script-array":        head + "[tool.hatch.envs.default.scripts]\nsetup = [\"ruff check\", \"sh -c \\\"pip install flask<2\\\"\"]\n",
		"hatch-env-vars-pip":        head + "[tool.hatch.envs.default.env-vars]\nPIP_INDEX_URL = \"https://mirror.example/simple\"\n",
		"hatch-plugin-type":         head + "[tool.hatch.envs.default]\ntype = \"conda\"\n",
		"hatch-type-not-string":     head + "[tool.hatch.envs.default]\ntype = 1\n",
		"hatch-overrides-not-table": head + "[tool.hatch.envs.default]\noverrides = \"x\"\n",
		"hatch-override-script":     head + "[tool.hatch.envs.test.overrides]\nplatform.linux.scripts = [{key = \"setup\", value = \"pip install flask<2\"}]\n",
		"hatch-override-post-cmd":   head + "[tool.hatch.envs.test.overrides]\nenv.CI.post-install-commands = [\"pip install flask<2\"]\n",
		"hatch-override-env-var":    head + "[tool.hatch.envs.test.overrides]\nmatrix.py.env-vars = [\"UV_INDEX_URL=https://mirror.example/simple\"]\n",
		"hatch-override-set-deps":   head + "[tool.hatch.envs.test.overrides]\nplatform.linux.set-dependencies = [\"flask<2\"]\n",
		"hatch-override-set-script": head + "[tool.hatch.envs.test.overrides]\nenv.CI.set-post-install-commands = [\"pip install flask<2\"]\n",
		"hatch-override-type":       head + "[tool.hatch.envs.test.overrides]\nplatform.linux.type = \"conda\"\n",
		"hatch-override-sources":    head + "[tool.hatch.envs.test.overrides]\nenv.CI.sources = [{key = \"flask\", value = \"./vendor/flask\"}]\n",
		"hatch-sources":             head + "[tool.hatch.sources]\nflask = \"./vendor/flask\"\n",
		"hatch-env-sources":         head + "[tool.hatch.envs.test.sources]\nflask = {git = \"https://github.com/example/flask\"}\n",
		"hatch-workspace":           head + "[tool.hatch.envs.test.workspace]\nmembers = [\"packages/*\"]\n",
		"hatch-extra-scripts":       head + "[tool.hatch.envs.test.extra-scripts]\nsetup = \"pip install flask<2\"\n",
		"hatch-script-abs-pip":      head + "[tool.hatch.envs.test.scripts]\nsetup = \"/usr/bin/pip install flask<2\"\n",
		"hatch-script-venv-pip":     head + "[tool.hatch.envs.test.scripts]\nsetup = \".venv/bin/pip install flask<2\"\n",
		"hatch-script-env-default":  head + "[tool.hatch.envs.test.scripts]\nsetup = \"{env:INSTALLER:pip} install flask<2\"\n",
		"hatch-custom-collector":    head + "[tool.hatch.env.collectors.custom]\npath = \"hatch_plugins.py\"\n",
		"hatch-env-var-installer":   head + "[tool.hatch.envs.test]\nenv-vars = {INSTALLER = \"pip\"}\npost-install-commands = [\"$INSTALLER install flask<2\"]\n",
		"hatch-override-script-kv":  head + "[tool.hatch.envs.test.overrides]\nmatrix.py.scripts = [\"setup=pip install flask<2\"]\n",
		"poetry-path":               head + "[tool.poetry.dependencies]\nflask = \"^2\"\nlib = {path = \"../lib\"}\n",
		"poetry-file":               head + "[tool.poetry.group.dev.dependencies]\nflask = \"^2\"\nlib = {file = \"dist/lib.whl\"}\n",
		"poetry-path-in-array":      head + "[tool.poetry.dependencies]\nflask = [{version = \"^2\", python = \"<3.12\"}, {path = \"../flask\", python = \">=3.12\"}]\n",
		"poetry-alternation":        head + "[tool.poetry.dependencies]\nflask = \"^1.0 || ^2.0\"\n",
		"poetry-version-not-string": head + "[tool.poetry.dependencies]\nflask = {version = 2}\n",
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

// PEP 735 groups (include-group included), uv and pdm dev-dependencies and poetry tables are
// read as declarations: covered by their own tool's lock when its pin satisfies the range, and
// otherwise a range that leaves the coordinate unresolved without making the result partial.
func TestResolveVersions_PyprojectGroupsAndToolTablesRead(t *testing.T) {
	const (
		head   = "[project]\nname = \"b\"\n\n"
		uvLock = "version = 1\n\n[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n"
		pdmLk  = "[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n"
	)
	covered := map[string]map[string]string{
		"groups-uv-lock":       {"pyproject.toml": head + "[dependency-groups]\ndev = [\"pytest\", {include-group = \"Web_Stack\"}]\nweb-stack = [\"flask>=2\"]\n", "uv.lock": uvLock},
		"groups-pdm-lock":      {"pyproject.toml": head + "[dependency-groups]\ntest = [\"flask>=2; python_version >= '3.9'\"]\n", "pdm.lock": pdmLk},
		"groups-exact-pin":     {"pyproject.toml": head + "[dependency-groups]\ndev = [\"flask==2.3.0\"]\n"},
		"uv-dev-uv-lock":       {"pyproject.toml": head + "[tool.uv]\ndev-dependencies = [\"flask>=2\"]\n", "uv.lock": uvLock},
		"pdm-dev-pdm-lock":     {"pyproject.toml": head + "[tool.pdm.dev-dependencies]\ntest = [\"flask>=2\"]\n", "pdm.lock": pdmLk},
		"poetry-caret-covered": {"pyproject.toml": "[tool.poetry.group.web.dependencies]\nflask = \"^2.1\"\n", "poetry.lock": pdmLk},
		// A parenthesized specifier with no space before it keys on the name alone.
		"project-paren-uv-lock":  {"pyproject.toml": head[:len(head)-1] + "dependencies = [\"Flask(>=2)\"]\n", "uv.lock": uvLock},
		"groups-paren-exact-pin": {"pyproject.toml": head + "[dependency-groups]\ndev = [\"Flask(==2.3.0)\"]\n"},
		"groups-paren-uv-lock":   {"pyproject.toml": head + "[dependency-groups]\ndev = [\"Flask(>=2)\"]\n", "uv.lock": uvLock},
		"uv-dev-paren-uv-lock":   {"pyproject.toml": head + "[tool.uv]\ndev-dependencies = [\"flask(>=2)\"]\n", "uv.lock": uvLock},
		"pdm-dev-paren-pdm-lock": {"pyproject.toml": head + "[tool.pdm.dev-dependencies]\ntest = [\"flask(>=2)\"]\n", "pdm.lock": pdmLk},
		"hatch-exact-pin":        {"pyproject.toml": head + "[tool.hatch.envs.default]\ndependencies = [\"flask==2.3.0\"]\n\n[tool.hatch.envs.lint]\nextra-dependencies = [\"flask==2.3.0\"]\n"},
		// Overrides that set no dependencies (here the matrix's interpreters) do not veto.
		"hatch-override-no-deps": {"pyproject.toml": head + "[tool.hatch.envs.test]\ndependencies = [\"flask==2.3.0\"]\n\n[[tool.hatch.envs.test.matrix]]\npython = [\"3.11\", \"3.12\"]\n\n[tool.hatch.envs.test.overrides]\nmatrix.python.platforms = [\"linux\"]\n"},
		// Commands, scripts and env-vars that name no installer, and the built-in type, do not
		// veto.
		"hatch-quiet-env": {"pyproject.toml": head + "[tool.hatch.envs.default]\ntype = \"virtual\"\ndependencies = [\"flask==2.3.0\"]\ninstaller = \"uv\"\npost-install-commands = [\"pre-commit install\"]\n\n[tool.hatch.envs.default.scripts]\ntest = \"pytest {args}\"\ncov = [\"coverage run -m pytest\", \"coverage report\"]\n\n[tool.hatch.envs.default.env-vars]\nPYTHONWARNINGS = \"error\"\n\n[tool.hatch.envs.default.overrides]\nenv.CI.scripts = [{key = \"test\", value = \"pytest -x\"}]\n"},
	}
	for name, files := range covered {
		t.Run(name, func(t *testing.T) {
			mustResolvedCompletePy(t, writeTree(t, files), "flask", "2.3.0")
		})
	}
	undecided := map[string]map[string]string{
		"groups-no-lock":          {"pyproject.toml": head + "[dependency-groups]\ndev = [\"flask>=2\"]\n"},
		"groups-stale-lock":       {"pyproject.toml": head + "[dependency-groups]\ndev = [\"flask>=2,<2.3\"]\n", "uv.lock": uvLock},
		"uv-dev-other-tool-lock":  {"pyproject.toml": head + "[tool.uv]\ndev-dependencies = [\"flask>=2\"]\n", "pdm.lock": pdmLk},
		"pdm-dev-other-tool-lock": {"pyproject.toml": head + "[tool.pdm.dev-dependencies]\ntest = [\"flask>=2\"]\n", "uv.lock": uvLock},
		"poetry-other-tool-lock":  {"pyproject.toml": "[tool.poetry.dependencies]\nflask = \"^2\"\n", "uv.lock": uvLock},
		"poetry-caret-stale-lock": {"pyproject.toml": "[tool.poetry.dependencies]\nflask = \"^2.4\"\n", "poetry.lock": pdmLk},
		// hatch has no lock, so no lock covers an environment's range.
		"hatch-dep-uv-lock":      {"pyproject.toml": head + "[tool.hatch.envs.default]\ndependencies = [\"flask>=2\"]\n", "uv.lock": uvLock},
		"hatch-extra-uv-lock":    {"pyproject.toml": head + "[tool.hatch.envs.test]\nextra-dependencies = [\"flask>=2\"]\n", "uv.lock": uvLock},
		"poetry-git":             {"pyproject.toml": "[tool.poetry.dependencies]\nflask = {git = \"https://github.com/pallets/flask\"}\n", "poetry.lock": pdmLk},
		"group-direct-reference": {"pyproject.toml": head + "[dependency-groups]\ndev = [\"flask @ https://example.com/flask-2.3.0.tar.gz\"]\n", "uv.lock": uvLock},
		// A parenthesized range a pin elsewhere does not satisfy: the name must still match.
		"project-paren-stale-lock": {"pyproject.toml": head[:len(head)-1] + "dependencies = [\"Flask(<2.3)\"]\n", "uv.lock": uvLock},
		"groups-paren-stale-lock":  {"pyproject.toml": head + "[dependency-groups]\ndev = [\"Flask(<2.3)\"]\n", "uv.lock": uvLock},
		"uv-dev-paren-stale-lock":  {"pyproject.toml": head + "[tool.uv]\ndev-dependencies = [\"flask(<2.3)\"]\n", "uv.lock": uvLock},
		"pdm-dev-paren-stale-lock": {"pyproject.toml": head + "[tool.pdm.dev-dependencies]\ntest = [\"flask(<2.3)\"]\n", "pdm.lock": pdmLk},
		// Poetry reads PEP 735 groups only from 2.2.0, so its lock does not resolve them.
		"groups-poetry-lock": {"pyproject.toml": head + "[dependency-groups]\ndev = [\"flask>=2\"]\n", "poetry.lock": pdmLk},
		"groups-paren-beside-another-pin": {"svc-a/requirements.txt": "flask==2.3.0\n",
			"svc-b/pyproject.toml": head + "[dependency-groups]\ndev = [\"Flask(<2.3)\"]\n"},
	}
	for name, files := range undecided {
		t.Run(name, func(t *testing.T) {
			mustUndecidedCompletePy(t, writeTree(t, files), "flask")
		})
	}
}

// tracker#543: a hatch environment's range beside a [project] pin makes the coordinate
// multi-valued, so the pin no longer resolves.
func TestResolveVersions_HatchEnvRangeBesideProjectPinUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pyproject.toml": "[project]\nname = \"b\"\ndependencies = [\"pyjwt==2.8.0\"]\n\n[tool.hatch.envs.default]\ndependencies = [\"pyjwt<2\"]\n",
	})
	mustUndecidedCompletePy(t, dir, "pyjwt")
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
			"deps.txt":  "# runtime\nflask>=3\npyjwt>=2.8\n",
		}, true, ">=2.8", false},
		// setuptools cuts an inline comment before parsing and reads pyjwt>=2.8; the reader does
		// not cut inline comments, so it withholds the file rather than read the line differently.
		{"setup.cfg file: line with an inline comment", map[string]string{
			"setup.cfg": "[options]\ninstall_requires = file: deps.txt\n",
			"deps.txt":  "flask>=3\npyjwt>=2.8  # tokens\n",
		}, false, "", true},
		// "file:" is a directive only at the start of the value; a dangling list holds the
		// literal requirement "file: base.txt,", which fails to parse.
		{"setup.cfg dangling file: list", map[string]string{
			"setup.cfg": "[options]\ninstall_requires =\n    file: base.txt,\n          extra.txt\n",
			"base.txt":  "flask>=3\n", "extra.txt": "pyjwt==2.8.0\n",
		}, false, "", true},
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

// tests_require is read as a test-time declaration in setup.py and setup.cfg, and a computed
// value takes the parse-failure path: a pin there at another version leaves the root pin
// unresolved.
func TestResolveVersions_TestsRequireVetoes(t *testing.T) {
	for name, body := range map[string]map[string]string{
		"setup.py literal":  {"svc/setup.py": "from setuptools import setup\nsetup(name='x', tests_require=['pyjwt==2.10.0'])\n"},
		"setup.py computed": {"svc/setup.py": "from setuptools import setup\nT = ['pyjwt==2.10.0']\nsetup(name='x', tests_require=T)\n"},
		"setup.cfg":         {"svc/setup.cfg": "[options]\ntests_require =\n    pyjwt==2.10.0\n"},
	} {
		t.Run(name, func(t *testing.T) {
			tree := map[string]string{"requirements.txt": "pyjwt==2.8.0\n"}
			for k, v := range body {
				tree[k] = v
			}
			dir := writeTree(t, tree)
			for i := 0; i < resolveRuns; i++ {
				mustUnresolvedPy(t, resolveVersion(t, dir, "pyjwt"))
			}
		})
	}
}

// setuptools reads a dashed setup.cfg option key (install-requires) as the underscored one, so a
// pin under a dashed key at another version leaves the root pin unresolved.
func TestResolveVersions_SetupCfgDashedKeysVeto(t *testing.T) {
	for _, key := range []string{"install-requires", "tests-require", "setup-requires"} {
		t.Run(key, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"requirements.txt": "pyjwt==2.8.0\n",
				"svc/setup.cfg":    "[options]\n" + key + " =\n    pyjwt==2.10.0\n",
			})
			for i := 0; i < resolveRuns; i++ {
				mustUnresolvedPy(t, resolveVersion(t, dir, "pyjwt"))
			}
		})
	}
}

// Surfaces the declaration readers read (setup.py/setup.cfg literals, setup_requires
// included, and [project].optional-dependencies) do not take the parse-failure path, but an
// unpinned, stale-locked or differently pinned entry in them still leaves another service's
// pin unresolved.
func TestResolveVersions_ReadDeclarationsVetoUnpinned(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"setup.py-install":             {"svc-b/setup.py": "from setuptools import setup\nsetup(name=\"b\", install_requires=[\"flask>=2\"])\n"},
		"setup.py-extras":              {"svc-b/setup.py": "from setuptools import setup\nsetup(name=\"b\", extras_require={\"web\": [\"flask\"]})\n"},
		"setup.cfg":                    {"svc-b/setup.cfg": "[metadata]\nname = b\n\n[options]\ninstall_requires =\n    flask>=2\n"},
		"setup.py-setup_requires pin":  {"svc-b/setup.py": "from setuptools import setup\nsetup(name=\"b\", setup_requires=[\"flask==3.0.0\"])\n"},
		"setup.cfg-setup_requires pin": {"svc-b/setup.cfg": "[options]\nsetup_requires =\n    flask==3.0.0\n"},
		"optional-dependencies stale lock": {
			"svc-b/pyproject.toml": "[project]\nname = \"b\"\n\n[project.optional-dependencies]\nweb = [\"flask>=3\"]\n",
			"svc-b/uv.lock":        "version = 1\n\n[[package]]\nname = \"flask\"\nversion = \"2.3.0\"\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			files["svc-a/requirements.txt"] = "flask==2.3.0\n"
			dir := writeTree(t, files)
			for i := 0; i < resolveRuns; i++ {
				mustUnresolvedPy(t, resolveVersion(t, dir, "flask"))
			}
		})
	}
}
