package jsanalysis

// pr_inherit_test.go — C3 PR-inheritance for the JS lane (PLAN-165). These tests drive the REAL
// exported trigger.RunBaseline → trigger.RunPRInherit decision over hand-authored npm lockfile
// fixtures, reusing the jsInventoryAdapter harness (inventory_sbom_test.go). The baseline is seeded
// the faithful way — a full RunBaseline over a vendored_repro fixture, storing a real state.Report +
// state.SBOM in an in-memory StateStore — so the diff RunPRInherit performs is the same
// changedPackages(baseline.SBOM, PRSBOM) the shipped GH adapter runs.
//
// Subprocess-free / §3-safe: no package manager, bundler, or target code runs; every dependency
// fact is read statically from the committed lockfiles. Case (b) of the C3 matrix (build-context
// change → re-analyse) is intentionally NOT built: it is gated on the open q18 ruling. Only (a)
// lockfile-change-reanalyses and (c) deps-unchanged-inherits are exercised here.

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

const prFixtureDir = invDir + "/pr"

// jsCodebase builds the vendored_repro CodebaseRef that routes a fixture dir through the JS lane,
// mirroring resolveSBOMForDir's acquisition. checkout.DetectLanguage classifies the dir as "js"
// from its inert index.js, matching jsInventoryAdapter.Language().
func jsCodebase(dir string) assessment.CodebaseRef {
	return assessment.CodebaseRef{
		Repo:        "example.com/js-fixture",
		Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
	}
}

// jsAssessOpts injects the JS inventory adapter into every pipeline seam the trigger run touches.
func jsAssessOpts() []pipeline.AssessOption {
	return []pipeline.AssessOption{pipeline.WithPlugin(jsInventoryAdapter{})}
}

// seedJSBaseline runs a REAL baseline over the fixture dir and returns the store it was committed
// to. The advisory work set is empty: these C3/C4 tests observe the SBOM/inherit machinery, not
// finding adjudication, so a whole-graph SBOM with zero findings is the honest baseline.
func seedJSBaseline(t *testing.T, dir, cursor string) statestore.StateStore {
	t.Helper()
	store := statestore.NewMemStore()
	_, err := trigger.RunBaseline(context.Background(), store, trigger.BaselineRequest{
		Subject:       trigger.Subject{Repo: "example.com/js-fixture", Revision: "main", ResolvedCommit: "base-sha"},
		Codebase:      jsCodebase(dir),
		Cursor:        cursor,
		AssessOptions: jsAssessOpts(),
	})
	if err != nil {
		t.Fatalf("RunBaseline(%s): %v", dir, err)
	}
	return store
}

// TestPRInherit_JS_LockfileChangeReanalyses is C3 case (a): a PR whose lockfile moves a resolved
// version (alpha 1.0.0 → 2.0.0) must NOT inherit. RunPRInherit diffs the PR SBOM against the stored
// baseline SBOM; the moved package changes its signature, so the fast path is refused and the moved
// package is named in ChangedPackages.
//
// Non-vacuity: an inherit-always producer (one that skipped the changedPackages diff and always took
// the fast path) would return Inherited:true here and fail. The exact-name assertion (npm\x00alpha)
// further rejects a diff that fired on the wrong package (e.g. the unchanged project root).
func TestPRInherit_JS_LockfileChangeReanalyses(t *testing.T) {
	store := seedJSBaseline(t, filepath.Join(prFixtureDir, "baseline"), "")

	prSBOM := resolveSBOMForDir(t, filepath.Join(prFixtureDir, "moved"))

	res, err := trigger.RunPRInherit(context.Background(), store, trigger.PRInheritRequest{
		Subject:       trigger.Subject{Repo: "example.com/js-fixture", ResolvedCommit: "pr-sha"},
		Codebase:      jsCodebase(filepath.Join(prFixtureDir, "moved")),
		PRSBOM:        prSBOM,
		AssessOptions: jsAssessOpts(),
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	if res.Inherited {
		t.Fatalf("case (a): a moved lockfile version must re-analyse, got fast-path inherit")
	}
	if !containsStr(res.ChangedPackages, "npm\x00alpha") {
		t.Fatalf("case (a): ChangedPackages must name the moved package npm\\x00alpha, got %q", res.ChangedPackages)
	}
	// The unchanged project root must NOT be reported as changed (its {ecosystem,name} signature is
	// version-independent and identical across the two heads).
	if containsStr(res.ChangedPackages, "npm\x00pr-project") {
		t.Errorf("case (a): unchanged project root wrongly reported changed: %q", res.ChangedPackages)
	}
}

// TestPRInherit_JS_DepsUnchangedInherits is C3 case (c) — THE MANDATORY CONTROL. The PR head has a
// byte-identical lockfile (identical resolved deps) and differs only in a non-dependency file (a
// README). ResolveSBOM reads only the lockfile, so the PR SBOM equals the baseline SBOM and the fast
// path MUST apply: Inherited:true, ChangedPackages empty.
//
// Non-vacuity: an always-re-analyse producer (the honest failure mode this control exists to catch)
// would return Inherited:false here and fail. Together with case (a) this pins the decision to the
// dependency diff, not to "did any file change".
func TestPRInherit_JS_DepsUnchangedInherits(t *testing.T) {
	store := seedJSBaseline(t, filepath.Join(prFixtureDir, "baseline"), "")

	prSBOM := resolveSBOMForDir(t, filepath.Join(prFixtureDir, "readme"))

	res, err := trigger.RunPRInherit(context.Background(), store, trigger.PRInheritRequest{
		Subject:       trigger.Subject{Repo: "example.com/js-fixture", ResolvedCommit: "pr-sha"},
		Codebase:      jsCodebase(filepath.Join(prFixtureDir, "readme")),
		PRSBOM:        prSBOM,
		AssessOptions: jsAssessOpts(),
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	if !res.Inherited {
		t.Fatalf("case (c): identical deps (README-only change) must inherit, got re-analysis (changed=%q)", res.ChangedPackages)
	}
	if len(res.ChangedPackages) != 0 {
		t.Fatalf("case (c): inherited fast path must report no changed packages, got %q", res.ChangedPackages)
	}
	if res.Report == nil || res.Report.Baseline == nil {
		t.Fatalf("case (c): inherited Report must carry a Baseline pointer, got %+v", res.Report)
	}
}

// TestPRInherit_JS_BuildContextChangeInheritsButDisclosesLimit is C3 case (b)'s honest Phase-1
// realization. The PR head changes ONLY build context (a Node `engines` constraint) with a
// byte-identical lockfile, so the resolved dependency set — and therefore the PR SBOM — is unchanged.
// RunPRInherit diffs the SBOM package set only (changedPackages → {version,direct,parents,children},
// all SBOM-derived; build context never reaches report.SBOM), so the change is invisible to the diff
// and the fast path applies: Inherited:true.
//
// That is NOT a silent stale inherit: inheritBaseline (trigger/state.go:171) discloses the gap on the
// inherited report as a quiet inherent_limit — report.ReasonBuildContextNotCompared — so a
// build-context-only change that inherited is distinguishable, on the artifact, from one that inherited
// because nothing changed. This test characterizes that landed, §3.1-honest behavior: the SBOM package
// set is the Phase-1 inheritance granularity, and the un-compared build-context axis is DECLARED, not
// inferred-safe. (Whether the program ACCEPTS this as C3(b) convergence — by-design — or additionally
// wants PR-time build-context conservatism — a PLAN-104 change to persist WorkspacePlan into the diffed
// SBOM — is the q18 ruling; the disclosure asserted here is true under either outcome.)
//
// Non-vacuity: a producer that dropped the inherent_limit disclosure on the fast path (claiming the §8
// checkbox without implementing the comparison) would leave Partiality without the note and fail — that
// omission is exactly the silent-stale-inherit this note exists to prevent.
func TestPRInherit_JS_BuildContextChangeInheritsButDisclosesLimit(t *testing.T) {
	store := seedJSBaseline(t, filepath.Join(prFixtureDir, "baseline"), "")

	prSBOM := resolveSBOMForDir(t, filepath.Join(prFixtureDir, "buildctx"))

	res, err := trigger.RunPRInherit(context.Background(), store, trigger.PRInheritRequest{
		Subject:       trigger.Subject{Repo: "example.com/js-fixture", ResolvedCommit: "pr-sha"},
		Codebase:      jsCodebase(filepath.Join(prFixtureDir, "buildctx")),
		PRSBOM:        prSBOM,
		AssessOptions: jsAssessOpts(),
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	// The build-context-only change does not move the SBOM package set → fast path.
	if !res.Inherited {
		t.Fatalf("case (b): a build-context-only change (identical lockfile) does not move the SBOM and must inherit, got re-analysis (changed=%q)", res.ChangedPackages)
	}
	if len(res.ChangedPackages) != 0 {
		t.Fatalf("case (b): the build-context change is invisible to the SBOM diff; ChangedPackages must be empty, got %q", res.ChangedPackages)
	}
	// ...but the inherited report DISCLOSES that build context was not compared (§3.1 honest-absent).
	if res.Report == nil {
		t.Fatalf("case (b): inherited Report missing")
	}
	if !notesHaveReason(res.Report.Partiality, report.ReasonBuildContextNotCompared) {
		t.Fatalf("case (b): the inherited report must DISCLOSE build_context_not_compared as an inherent_limit (a build-context-only change must not inherit silently); Partiality=%+v", res.Report.Partiality)
	}
}

// TestSBOM_JS_DeterministicEncoding guards the C3 determinism claim: resolving the same fixture's
// SBOM twice must produce byte-identical canonical encodings. The diamond fixture carries two
// versions of one package (shared@1.0.0 and shared@2.0.0), so a non-stable ordering (the old
// sort.Slice defect the convergence C3 names) would surface here as a diff between the two encodes.
//
// Non-vacuity: an SBOM producer that ordered packages or relationships by map iteration would emit a
// different byte sequence on the second resolve and fail this equality.
func TestSBOM_JS_DeterministicEncoding(t *testing.T) {
	dir := filepath.Join(sbomFixtureDir, "diamond-two-versions")

	first := resolveSBOMForDir(t, dir)
	second := resolveSBOMForDir(t, dir)

	// report.SBOM is an all-slice struct (no maps), so json.Marshal is the canonical encoding the
	// statestore content-addresses on (statestore.marshalCanonical == json.Marshal); a stable
	// package/relationship order is what makes the two encodes equal.
	fb, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}
	sb, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second: %v", err)
	}
	if string(fb) != string(sb) {
		t.Fatalf("non-deterministic SBOM encoding across two resolves:\n  first=%s\n second=%s", fb, sb)
	}

	// The two same-name versions must appear in a stable relative order within the single encoding.
	iShared1 := indexOfSub(string(fb), `"pkg:npm/shared@1.0.0"`)
	iShared2 := indexOfSub(string(fb), `"pkg:npm/shared@2.0.0"`)
	if iShared1 < 0 || iShared2 < 0 {
		t.Fatalf("determinism: both shared versions must be present in the encoding: %s", fb)
	}
	if iShared1 > iShared2 {
		t.Errorf("determinism: shared@1.0.0 must sort before shared@2.0.0 (version-stable order), got 1@%d 2@%d", iShared1, iShared2)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func indexOfSub(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
