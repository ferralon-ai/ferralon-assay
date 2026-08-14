package trigger_test

// PLAN-173 C4 — PR inheritance fires on Python dependency / build-context changes, and ONLY on
// those. This is an EXTERNAL test package (trigger_test): it drives only the exported trigger
// surface (RunBaseline / ResolveSBOM / RunPRInherit) and edits no package-internal or anvil-owned
// file (C6). It reuses the C3 in-process Python-plugin adapter (pythonInventoryPlugin), so every
// SBOM here — baseline and PR-head alike — is produced by the REAL pythonanalysis.ResolveInventory
// over a vendored_repro fixture, never a hand-fabricated report.SBOM fed straight to the diff.
//
// The detector under test is trigger's changedPackages(baseline.SBOM, req.PRSBOM), reached through
// RunPRInherit: an empty diff takes the Inherited fast path, a non-empty diff forces re-analysis.
// changedPackages keys on (ecosystem, name) -> version, so a build-context edit is "relevant" iff
// it moves the RESOLVED inventory — a package added/removed or a version repinned. That is exactly
// the property C4 wants: the four positive shapes each genuinely repin/add a distribution through
// the real resolver; the two negatives (a .py comment, an unrelated file) leave the resolved
// inventory byte-identical and so must inherit.
//
// The negatives are load-bearing (fixture-homogeneity-masks-honesty-bugs): a detector that returned
// "relevant" for every diff would pass all four positives and be useless; only the negatives, which
// MUST return Inherited=true, can catch it. TestC4Control_SameBaselineDiscriminates makes that
// explicit — the same diff-free baseline reddens the instant the PR-head inventory truly changes.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// c4Tree materializes a vendored_repro tree from a relpath->content map and returns its absolute
// path. Every tree carries an app.py so checkout.DetectLanguage's source-dominance walk classifies
// it as Python and the inventory stage routes to the python plugin (same premise as the C3 harness).
func c4Tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return dir
}

func c4Codebase(dir string) assessment.CodebaseRef {
	return assessment.CodebaseRef{
		Repo:        "example.com/pyapp",
		Revision:    "sha",
		Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
	}
}

func c4Plugin() []pipeline.AssessOption {
	return []pipeline.AssessOption{pipeline.WithPlugin(pythonInventoryPlugin{})}
}

// c4SeedBaseline runs a REAL baseline scan over the baseline fixture and stores it, so the diff
// RunPRInherit performs is against a genuinely-resolved baseline SBOM, not a seeded literal. The
// baseline work set is empty (no findings needed): C4 is about the SBOM diff, not verdicts.
func c4SeedBaseline(t *testing.T, dir string) *statestore.MemStore {
	t.Helper()
	store := statestore.NewMemStore()
	if _, err := trigger.RunBaseline(context.Background(), store, trigger.BaselineRequest{
		Subject:       trigger.Subject{Repo: "example.com/pyapp", ResolvedCommit: "base-sha"},
		Codebase:      c4Codebase(dir),
		AssessOptions: c4Plugin(),
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	return store
}

// c4PRHeadSBOM resolves the PR head's whole-graph SBOM through the real inventory path (the same
// producer the baseline used), so both sides of the diff are resolver output over real manifests.
func c4PRHeadSBOM(t *testing.T, dir string) report.SBOM {
	t.Helper()
	sbom, _, err := trigger.ResolveSBOM(context.Background(), trigger.ResolveSBOMRequest{
		Codebase:      c4Codebase(dir),
		AssessOptions: c4Plugin(),
	})
	if err != nil {
		t.Fatalf("ResolveSBOM (PR head): %v", err)
	}
	return sbom
}

// c4Inherited seeds a baseline from baseDir, resolves the PR head from prDir, and returns whether
// RunPRInherit took the Inherited fast path (deps unchanged) — the observable C4 decision.
func c4Inherited(t *testing.T, baseDir, prDir string) (bool, []string) {
	t.Helper()
	store := c4SeedBaseline(t, baseDir)
	prSBOM := c4PRHeadSBOM(t, prDir)
	res, err := trigger.RunPRInherit(context.Background(), store, trigger.PRInheritRequest{
		Subject:       trigger.Subject{Repo: "example.com/pyapp", ResolvedCommit: "pr-sha"},
		Codebase:      c4Codebase(prDir),
		PRSBOM:        prSBOM,
		AssessOptions: c4Plugin(),
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	return res.Inherited, res.ChangedPackages
}

// --- fixtures (compact, valid manifests; real distribution names + versions) -----------------
//
// Hashes are omitted deliberately: changedPackages keys on (ecosystem, name, version) only, so a
// declared digest is irrelevant here and omitting it avoids carrying any unverified hash. The
// versions and dependency couplings are real PyPI facts (jinja2 depends on MarkupSafe>=2.0;
// requests[socks] pulls PySocks; markupsafe 3.0.3 itself requires Python >=3.9), so the resolver
// derives real PURLs — nothing is fabricated.

// jinjaLock is a pdm.lock pinning jinja2 (direct) -> markupsafe (transitive).
func jinjaLock(jinjaVer, markupsafeVer string) string {
	return fmt.Sprintf(`# pdm.lock
[[package]]
name = "jinja2"
version = "%s"
dependencies = ["MarkupSafe>=2.0"]

[[package]]
name = "markupsafe"
version = "%s"
`, jinjaVer, markupsafeVer)
}

// interpLock is a pdm.lock whose declared target interpreter (metadata.targets.requires_python)
// governs which markupsafe release the resolver could pin: markupsafe 3.0.3 requires Python >=3.9,
// so a repo declaring >=3.7 locks the older 2.1.5 and one declaring >=3.9 locks 3.0.3. The declared
// interpreter is the build-context input; its INVENTORY-visible consequence — the markupsafe repin —
// is what changedPackages observes (an interpreter bump that repinned nothing would correctly
// inherit; declared-interpreter data is not itself a package coordinate the SBOM carries).
func interpLock(requiresPython, markupsafeVer string) string {
	return fmt.Sprintf(`# pdm.lock
[metadata]
groups = ["default"]

[[metadata.targets]]
requires_python = "%s"

[[package]]
name = "jinja2"
version = "3.1.2"
dependencies = ["MarkupSafe>=2.0"]

[[package]]
name = "markupsafe"
version = "%s"
`, requiresPython, markupsafeVer)
}

// requestsLock is a pdm.lock for a project depending on requests. With socks=false only requests is
// locked; with socks=true the requests[socks] extra was selected and re-locked, so PySocks enters
// the locked closure (guarded by the extra marker the lock records). The extras-selection change is
// thus visible to the detector as the added pysocks distribution.
func requestsLock(socks bool) string {
	if !socks {
		return `# pdm.lock
[[package]]
name = "requests"
version = "2.31.0"
`
	}
	return `# pdm.lock
[[package]]
name = "requests"
version = "2.31.0"
dependencies = ["PySocks>=1.5.6 ; extra == 'socks'"]

[[package]]
name = "pysocks"
version = "1.7.1"
`
}

// pyprojDeps is a PEP 621 pyproject.toml whose [project].dependencies list is the resolved set.
func pyprojDeps(depsInner string) string {
	return fmt.Sprintf(`[project]
name = "pyapp"
version = "0.1.0"
dependencies = [%s]
`, depsInner)
}

// TestC4_PRInherit_DetectsDependencyAndBuildContextChanges is the C4 table: four positive shapes
// (lockfile repin, pyproject dependency list, extras selection, declared interpreter) each move the
// resolved inventory and so must NOT inherit; two negatives (a .py comment, an unrelated file) leave
// it identical and so MUST inherit. Every SBOM on both sides is real resolver output over a
// vendored_repro fixture.
func TestC4_PRInherit_DetectsDependencyAndBuildContextChanges(t *testing.T) {
	const app = "import jinja2\n"
	const reqApp = "import requests\n"

	// The negatives share this exact lockfile with their baseline, so only the non-manifest file
	// differs and the resolved inventory is byte-identical.
	baseLock := jinjaLock("3.1.2", "3.0.3")

	tests := []struct {
		name          string
		baseline      map[string]string
		prhead        map[string]string
		wantInherited bool
	}{
		{
			name:     "lockfile_repin_is_relevant",
			baseline: map[string]string{"pdm.lock": jinjaLock("3.1.2", "3.0.3"), "app.py": app},
			prhead:   map[string]string{"pdm.lock": jinjaLock("3.1.3", "3.0.3"), "app.py": app},
		},
		{
			name:     "pyproject_dependency_added_is_relevant",
			baseline: map[string]string{"pyproject.toml": pyprojDeps(`"jinja2==3.1.2"`), "app.py": app},
			prhead:   map[string]string{"pyproject.toml": pyprojDeps(`"jinja2==3.1.2", "click==8.1.7"`), "app.py": app},
		},
		{
			name:     "extras_selection_pulls_dependency_is_relevant",
			baseline: map[string]string{"pdm.lock": requestsLock(false), "app.py": reqApp},
			prhead:   map[string]string{"pdm.lock": requestsLock(true), "app.py": reqApp},
		},
		{
			name:     "interpreter_declaration_repins_is_relevant",
			baseline: map[string]string{"pdm.lock": interpLock(">=3.7", "2.1.5"), "app.py": app},
			prhead:   map[string]string{"pdm.lock": interpLock(">=3.9", "3.0.3"), "app.py": app},
		},
		{
			name:          "py_comment_only_is_not_relevant",
			baseline:      map[string]string{"pdm.lock": baseLock, "app.py": app},
			prhead:        map[string]string{"pdm.lock": baseLock, "app.py": "import jinja2  # touch: no dependency change\n"},
			wantInherited: true,
		},
		{
			name:          "unrelated_file_is_not_relevant",
			baseline:      map[string]string{"pdm.lock": baseLock, "app.py": app},
			prhead:        map[string]string{"pdm.lock": baseLock, "app.py": app, "README.md": "# pyapp\n"},
			wantInherited: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseDir := c4Tree(t, tc.baseline)
			prDir := c4Tree(t, tc.prhead)
			inherited, changed := c4Inherited(t, baseDir, prDir)
			if inherited != tc.wantInherited {
				t.Errorf("Inherited = %v, want %v (changedPackages = %v)", inherited, tc.wantInherited, changed)
			}
			if tc.wantInherited && len(changed) != 0 {
				t.Errorf("fast path must report no changed packages, got %v", changed)
			}
			if !tc.wantInherited && len(changed) == 0 {
				t.Errorf("relevant change reported zero changed packages — the diff did not move the resolved inventory")
			}
		})
	}
}

// TestC4Control_SameBaselineDiscriminates is the load-bearing control the C4 negatives rest on. It
// pins the SAME diff-free baseline and shows the Inherited decision tracks the resolved inventory,
// not the call: a PR-head whose lockfile is identical (only a .py comment differs) inherits, and the
// instant the lockfile repins a dependency it does not. A detector wired unconditionally "relevant"
// would fail the first assertion (the negatives would go red); one wired unconditionally "inherit"
// would fail the second. Only a detector reading the real SBOM diff passes both.
func TestC4Control_SameBaselineDiscriminates(t *testing.T) {
	baseline := map[string]string{"pdm.lock": jinjaLock("3.1.2", "3.0.3"), "app.py": "import jinja2\n"}

	diffFree := map[string]string{"pdm.lock": jinjaLock("3.1.2", "3.0.3"), "app.py": "import jinja2  # comment only\n"}
	if inherited, changed := c4Inherited(t, c4TreeDir(t, baseline), c4TreeDir(t, diffFree)); !inherited {
		t.Errorf("diff-free change did not inherit (changed = %v) — the negative rows are only load-bearing if this holds", changed)
	}

	repinned := map[string]string{"pdm.lock": jinjaLock("3.1.3", "3.0.3"), "app.py": "import jinja2\n"}
	if inherited, _ := c4Inherited(t, c4TreeDir(t, baseline), c4TreeDir(t, repinned)); inherited {
		t.Error("a real dependency repin inherited — the fast path is unconditional, so the negatives prove nothing")
	}
}

// c4TreeDir is c4Tree with the files map materialized freshly each call (distinct temp dirs so the
// control's baseline/PR trees never alias).
func c4TreeDir(t *testing.T, files map[string]string) string {
	t.Helper()
	return c4Tree(t, files)
}
