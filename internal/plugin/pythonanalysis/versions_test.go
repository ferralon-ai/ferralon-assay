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
