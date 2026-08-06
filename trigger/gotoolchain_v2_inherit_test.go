// gotoolchain_v2_inherit_test.go
//
// How an `undetermined` row travels through the two paths that do NOT re-derive it: the PR-inherit
// fast path (re-emits the baseline verbatim) and the re-analyze/earnest merge loops (replace what
// they re-evaluated, inherit the rest).
//
// This is where M2's residual exposure window lived. Under v1 an unadjudicable advisory left
// advisories[] entirely, so the merge loops had to DELETE an inherited row by id — and the fast path,
// which re-derives nothing, could not delete anything and carried a pre-M2 not_exploitable forward
// until the default branch was re-scanned. Under v2 the fresh evaluation produces a row, so the
// ordinary keyed merge replaces the stale one, and the fast path carries an honest non-verdict
// forward instead of a stale claim.
package trigger

import (
	"context"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// goAssessOptions wires the same hermetic seams runGoBaseline uses — a fixed checkout at buildDir
// and the real go.mod parse with empty analysis results — so the merge paths run the REAL pipeline
// over a real manifest rather than a hand-seeded artifact store.
func goAssessOptions(buildDir string) []pipeline.AssessOption {
	return []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: buildDir, lang: "go"}),
		pipeline.WithPlugin(goManifestPlugin{}),
	}
}

// undeterminedBaseline is a stored v2 baseline holding one real candidate plus one undetermined
// toolchain row and its limit — the shape a post-bump baseline run over a Go repo produces.
func undeterminedBaseline() (*memStore, *report.Report) {
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.6"}
	baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackage(pkg).
		ReachableCandidate(report.Advisory{ID: "GO-2021-0113", Source: "osv"}, &pkg, "h → s", "").
		Undetermined(report.Advisory{ID: "GO-2021-0264", Source: "osv"}, nil, report.ReasonGoToolchainNotScanned).
		AddPartiality(report.PartialityNote{Reason: report.ReasonGoToolchainNotScanned, Ecosystem: "Go"}).
		WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: "GO-2021-0113"}).
		Build()
	return &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM, Cursor: "GO-2021-0113"}}, &baseline
}

// TestPRInherit_FastPathCarriesUndeterminedForward is the fast path's whole obligation. It
// re-derives nothing by contract, so what it must not do is quietly upgrade a non-verdict into a
// verdict — or drop the row and render the PR clean.
func TestPRInherit_FastPathCarriesUndeterminedForward(t *testing.T) {
	store, baseline := undeterminedBaseline()

	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		PRSBOM:     baseline.SBOM,
		Advisories: []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}},
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	if !res.Inherited {
		t.Fatalf("want the fast path, got re-analysis (%v)", res.ChangedPackages)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatalf("inherited report invalid: %v", err)
	}

	var found bool
	for _, f := range res.Report.Advisories {
		if f.Advisory.ID != "GO-2021-0264" {
			continue
		}
		found = true
		if f.Verdict != report.VerdictUndetermined {
			t.Errorf("inherited GO-2021-0264 verdict = %q, want it carried forward as undetermined", f.Verdict)
		}
		if f.UndeterminedReason != report.ReasonGoToolchainNotScanned {
			t.Errorf("inherited reason = %q, want it preserved verbatim", f.UndeterminedReason)
		}
	}
	if !found {
		t.Error("GO-2021-0264 vanished on the fast path — the PR would render as though it had been assessed")
	}
	// The baseline's coverage limit must come with it, for the same reason.
	var sawLimit bool
	for _, n := range res.Report.Partiality {
		if n.Reason == report.ReasonGoToolchainNotScanned {
			sawLimit = true
		}
	}
	if !sawLimit {
		t.Error("the baseline's coverage limit was dropped on the fast path")
	}
}

// TestReanalyze_FreshUndeterminedReplacesAStaleInheritedVerdict is the M2 residual closing. The
// baseline carries a pre-fix `not_exploitable` for a toolchain advisory; this head's fresh evaluation
// establishes nothing, so the row it emits must REPLACE the stale claim rather than sit beside it.
//
// The replacement runs through the ordinary (id, source) merge, which is why the fresh undetermined
// finding has to be harvested before the `pkg == nil` skip: a toolchain advisory carries no SBOM
// package, so the skip would drop it and leave the claim standing.
func TestReanalyze_FreshUndeterminedReplacesAStaleInheritedVerdict(t *testing.T) {
	buildDir := writeGoMod(t, "module example.com/target\n\ngo 1.20\n")
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.6"}

	// A baseline written before the fix: the unestablished safety claim, as a first-class row.
	stale := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackage(pkg).
		NotExploitable(report.Advisory{ID: "GO-2021-0264", Source: "corpus"}, nil,
			"vulnerable_symbol_absent", "no reachable path to the advisory symbol was found").
		WithProvenance(report.Provenance{CommitSHA: "base-sha", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
	store := &memStore{state: &statestore.State{Report: &stale, SBOM: stale.SBOM, Cursor: "GO-2021-0264"}}

	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:  Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase: assessment.CodebaseRef{Repo: "r", Revision: "main"},
		// A changed dependency set forces the re-analyze path.
		PRSBOM:        report.SBOM{Packages: []report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.9.9"}}},
		Advisories:    []assessment.VulnRef{{ID: "GO-2021-0264", Source: "corpus"}},
		AssessOptions: goAssessOptions(buildDir),
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	if res.Inherited {
		t.Fatal("want re-analysis on a changed dependency set")
	}

	var rows int
	for _, f := range res.Report.Advisories {
		if f.Advisory.ID != "GO-2021-0264" {
			continue
		}
		rows++
		if f.Verdict != report.VerdictUndetermined {
			t.Errorf("GO-2021-0264 verdict = %q, want undetermined — this pass established nothing, so the baseline's claim must not survive", f.Verdict)
		}
		if f.Evidence.Basis != "" {
			t.Errorf("GO-2021-0264 still carries basis %q from the stale row", f.Evidence.Basis)
		}
	}
	if rows != 1 {
		t.Errorf("GO-2021-0264 appears %d times, want exactly 1 (the fresh row replacing the stale one)", rows)
	}
	var sawLimit bool
	for _, n := range res.Report.Partiality {
		if n.Reason == report.ReasonGoToolchainNotScanned {
			sawLimit = true
		}
	}
	if !sawLimit {
		t.Error("the re-analyzed report carries an undetermined row with no coverage limit to explain it")
	}
}

// TestEarnestRun_FreshUndeterminedReplacesAStaleInheritedVerdict is the same property on the
// CVE-watch path, which merges over the PRIOR report rather than a baseline and takes its package
// from the OSV query rather than from the pipeline. That second difference matters: the OSV package
// must not end up on a toolchain row, or the SBOM coordinate the guard removed comes back.
func TestEarnestRun_FreshUndeterminedReplacesAStaleInheritedVerdict(t *testing.T) {
	buildDir := writeGoMod(t, "module example.com/target\n\ngo 1.20\n")
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0"}

	stale := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackage(pkg).
		NotExploitable(report.Advisory{ID: "CVE-2023-39325", Source: "osv"}, &pkg,
			"vulnerable_symbol_absent", "no reachable path to the advisory symbol was found").
		WithProvenance(report.Provenance{CommitSHA: "base-sha", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
	store := &memStore{state: &statestore.State{Report: &stale, SBOM: stale.SBOM, Cursor: ""}}

	res, err := RunCVEWatch(context.Background(), store,
		&fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: "CVE-2023-39325", Package: pkg}}}},
		CVEWatchRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			AssessOptions: goAssessOptions(buildDir),
		})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Heartbeat {
		t.Fatal("want an earnest run: the advisory is not in the stored cursor")
	}

	var rows int
	for _, f := range res.Report.Advisories {
		if f.Advisory.ID != "CVE-2023-39325" {
			continue
		}
		rows++
		if f.Verdict != report.VerdictUndetermined {
			t.Errorf("CVE-2023-39325 verdict = %q, want undetermined", f.Verdict)
		}
		if f.Package != nil {
			t.Errorf("CVE-2023-39325 carries package %+v — the Go toolchain is not an SBOM dependency, and pairing the advisory's module with a go1.x.y release names a coordinate that does not exist", f.Package)
		}
	}
	if rows != 1 {
		t.Errorf("CVE-2023-39325 appears %d times, want exactly 1", rows)
	}
}
