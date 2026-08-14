package trigger

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// --- C1: the diff compares relationships, not just {ecosystem, name} -> version -----

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// versionOnlyChanged replicates the PRE-PLAN-104 diff (indexSBOM keyed on
// ecosystem\x00name -> version). It is the control: a relationship-only delta must be
// INVISIBLE to it, proving the fixtures isolate the relationship axis and the new
// changedPackages is measuring that axis rather than an incidental version difference.
func versionOnlyChanged(baseline, candidate report.SBOM) []string {
	idx := func(s report.SBOM) map[string]string {
		m := make(map[string]string, len(s.Packages))
		for _, p := range s.Packages {
			m[p.Ecosystem+"\x00"+p.Name] = p.Version
		}
		return m
	}
	base, cand := idx(baseline), idx(candidate)
	var out []string
	for k, bv := range base {
		if cv, ok := cand[k]; !ok || cv != bv {
			out = append(out, k)
		}
	}
	for k := range cand {
		if _, ok := base[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}

func TestChangedPackages_DetectsDirectTransitiveFlip_C1(t *testing.T) {
	app := report.Package{Ecosystem: "Go", Name: "example.com/app", Version: "v1.0.0", PURL: "pkg:golang/example.com/app@v1.0.0", Direct: true}
	depDirect := report.Package{Ecosystem: "Go", Name: "example.com/dep", Version: "v1.2.0", PURL: "pkg:golang/example.com/dep@v1.2.0", Direct: true}
	depTransitive := depDirect
	depTransitive.Direct = false // ONLY the direct/transitive bit differs

	base := report.SBOM{Packages: []report.Package{app, depDirect}}
	head := report.SBOM{Packages: []report.Package{app, depTransitive}}

	changed := changedPackages(base, head)
	if !contains(changed, "Go\x00example.com/dep") {
		t.Fatalf("a direct->transitive flip must be a change; changed=%v", changed)
	}
	// Control: version-only comparison sees nothing (the version is identical).
	if len(versionOnlyChanged(base, head)) != 0 {
		t.Fatal("control is vacuous: the pre-cycle version-only diff already reports a change, so the fixture is not isolating the relationship axis")
	}
}

func TestChangedPackages_DetectsParentEdgeMove_C1(t *testing.T) {
	app := report.Package{Ecosystem: "Go", Name: "example.com/app", Version: "v1.0.0", PURL: "pkg:golang/example.com/app@v1.0.0", Direct: true}
	mid := report.Package{Ecosystem: "Go", Name: "example.com/mid", Version: "v1.0.0", PURL: "pkg:golang/example.com/mid@v1.0.0", Direct: true}
	leaf := report.Package{Ecosystem: "Go", Name: "example.com/leaf", Version: "v2.0.0", PURL: "pkg:golang/example.com/leaf@v2.0.0", Direct: false}

	pkgs := []report.Package{app, mid, leaf}
	// baseline: app -> leaf. head: mid -> leaf. Same package set + versions; only leaf's
	// parent moved (app -> mid). Its version and direct bit are untouched.
	base := report.SBOM{Packages: pkgs, Relationships: []report.Relationship{{Parent: app.Key(), Child: leaf.Key()}}}
	head := report.SBOM{Packages: pkgs, Relationships: []report.Relationship{{Parent: mid.Key(), Child: leaf.Key()}}}

	changed := changedPackages(base, head)
	if !contains(changed, "Go\x00example.com/leaf") {
		t.Fatalf("a moved parent edge must be a change for the child; changed=%v", changed)
	}
	if len(versionOnlyChanged(base, head)) != 0 {
		t.Fatal("control is vacuous: version-only diff already differs, fixture not isolating the edge axis")
	}
}

// --- C2: the relevance rule is explicit and fails toward re-analysis ----------------

// TestRelevanceRule_SuppressesDescendantVersionChurn is the ONE deliberate suppression:
// a descendant's version bump does not, by itself, re-flag its parent. The descendant
// re-runs on its own delta; re-running the parent would evaluate the same advisories
// against the same coordinate for no applicability change.
func TestRelevanceRule_SuppressesDescendantVersionChurn_C2(t *testing.T) {
	app := report.Package{Ecosystem: "Go", Name: "example.com/app", Version: "v1.0.0", PURL: "pkg:golang/example.com/app@v1.0.0", Direct: true}
	leafOld := report.Package{Ecosystem: "Go", Name: "example.com/leaf", Version: "v2.0.0", PURL: "pkg:golang/example.com/leaf@v2.0.0", Direct: false}
	leafNew := report.Package{Ecosystem: "Go", Name: "example.com/leaf", Version: "v2.1.0", PURL: "pkg:golang/example.com/leaf@v2.1.0", Direct: false}

	base := report.SBOM{Packages: []report.Package{app, leafOld}, Relationships: []report.Relationship{{Parent: app.Key(), Child: leafOld.Key()}}}
	head := report.SBOM{Packages: []report.Package{app, leafNew}, Relationships: []report.Relationship{{Parent: app.Key(), Child: leafNew.Key()}}}

	changed := changedPackages(base, head)
	if !contains(changed, "Go\x00example.com/leaf") {
		t.Fatalf("the descendant whose version bumped must itself be changed; changed=%v", changed)
	}
	// app's version, direct bit, and neighbour NAMES are unchanged (leaf is still its
	// child, by name) — so app is suppressed. This is the rule's only quiet case.
	if contains(changed, "Go\x00example.com/app") {
		t.Fatalf("a parent must NOT re-flag on a descendant's version bump alone; changed=%v", changed)
	}
}

// TestRelevanceRule_AmbiguousResolvesToChanged is the failure-direction guarantee: when
// the head SBOM cannot confirm a package's relationships are unchanged (its edge data is
// absent while the baseline's was present), the rule resolves to CHANGED, never inherit.
//
// Mutation control: drop the `children`/`parents` fields from packageSignature (making
// the signature version+direct only) and this test goes red — the package would then
// look unchanged and inherit silently. That is the suppression-inversion C2 requires.
func TestRelevanceRule_AmbiguousResolvesToChanged_C2(t *testing.T) {
	app := report.Package{Ecosystem: "Go", Name: "example.com/app", Version: "v1.0.0", PURL: "pkg:golang/example.com/app@v1.0.0", Direct: true}
	leaf := report.Package{Ecosystem: "Go", Name: "example.com/leaf", Version: "v2.0.0", PURL: "pkg:golang/example.com/leaf@v2.0.0", Direct: false}

	pkgs := []report.Package{app, leaf}
	// baseline knows app -> leaf; head has the SAME packages/versions but NO edge data
	// (its lane inventory could not resolve relationships). app's child set went from
	// {leaf} to {} — an ambiguous "can't confirm unchanged", which must resolve to changed.
	base := report.SBOM{Packages: pkgs, Relationships: []report.Relationship{{Parent: app.Key(), Child: leaf.Key()}}}
	head := report.SBOM{Packages: pkgs} // no relationships

	changed := changedPackages(base, head)
	if !contains(changed, "Go\x00example.com/app") {
		t.Fatalf("when head cannot confirm app's edges are unchanged, app must be changed (fail toward re-analysis); changed=%v", changed)
	}
}

// --- C3: an incomplete comparison is disclosed on the fast path ---------------------

func TestPRInherit_DiscloseIncompleteComparison_C3(t *testing.T) {
	headLimit := report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"}

	cases := []struct {
		name        string
		diffLimits  []report.PartialityNote
		wantHasNote bool
	}{
		{"(i) genuinely unchanged", nil, false},
		{"(ii) unchanged-looking because head inventory unavailable", []report.PartialityNote{headLimit}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, baseline := seedBaseline(t)
			res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
				Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
				PRSBOM:     baseline.SBOM, // identical deps -> fast path for BOTH cases
				DiffLimits: tc.diffLimits,
			})
			if err != nil {
				t.Fatalf("RunPRInherit: %v", err)
			}
			if !res.Inherited {
				t.Fatalf("both (i) and (ii) must take the fast path; got re-analysis")
			}
			got := hasNoteReason(res.Report.Partiality, "no_manifest")
			if got != tc.wantHasNote {
				t.Fatalf("head-inventory disclosure presence = %v, want %v (notes=%+v)", got, tc.wantHasNote, res.Report.Partiality)
			}
		})
	}
	// The two fast-path Reports are distinguishable — (ii) names what could not be
	// compared, (i) does not. Dropping req.DiffLimits from inheritBaseline collapses the
	// distinction (the mutation control this asserts against).
}

// --- C4: CVE-watch's query set is the whole stored inventory ------------------------

// inventoryAwareOSV returns targetAdvisory for targetPkg ONLY if targetPkg was in the
// queried coordinate set — so a package absent from the stored SBOM is never discovered.
// This makes the whole-inventory-vs-advisory-keyed control real rather than vacuous.
type inventoryAwareOSV struct {
	targetPkg      report.Package
	targetAdvisory string
	lastPkgs       []report.Package
}

func (o *inventoryAwareOSV) QueryBatch(_ context.Context, pkgs []report.Package) (OSVResult, error) {
	o.lastPkgs = pkgs
	for _, p := range pkgs {
		if p.Ecosystem == o.targetPkg.Ecosystem && p.Name == o.targetPkg.Name && p.Version == o.targetPkg.Version {
			return OSVResult{Advisories: []OSVAdvisory{{ID: o.targetAdvisory, Package: o.targetPkg}}}, nil
		}
	}
	return OSVResult{}, nil
}

func TestCVEWatch_EarnestOnNonAdvisoryInventoryPackage_C4(t *testing.T) {
	// A package that appeared in NO advisory of the baseline's work set, present in the
	// stored inventory only because PLAN-100 made the SBOM whole-graph.
	nonAdvisory := report.Package{Ecosystem: "Go", Name: "example.com/quiet", Version: "v1.0.0"}
	newAdvisory := "GO-2099-9999"

	// Whole-inventory baseline: the SBOM contains the non-advisory package. Cursor does
	// not contain the new advisory.
	base := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base"}).
		AddPackage(nonAdvisory).
		WithProvenance(report.Provenance{CommitSHA: "base", AdvisoryCursor: ""}).
		Build()
	store := &memStore{state: &statestore.State{Report: &base, SBOM: base.SBOM, Cursor: ""}}

	osv := &inventoryAwareOSV{targetPkg: nonAdvisory, targetAdvisory: newAdvisory}
	res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
		Subject:  Subject{Repo: "r", ResolvedCommit: "base"},
		Codebase: assessment.CodebaseRef{Repo: "r"},
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Heartbeat {
		t.Fatal("a newly disclosed advisory for an in-inventory non-advisory package must force an EARNEST run, not a heartbeat")
	}
	if !contains(res.NewAdvisories, newAdvisory) {
		t.Fatalf("earnest run must name the new advisory; got %v", res.NewAdvisories)
	}
	// The stub must actually have been queried with the package's triple — a pass cannot
	// come from the client ignoring its input.
	found := false
	for _, p := range osv.lastPkgs {
		if p.Name == nonAdvisory.Name && p.Version == nonAdvisory.Version {
			found = true
		}
	}
	if !found {
		t.Fatalf("CVE-watch did not query OSV with the non-advisory package's triple; queried=%v", osv.lastPkgs)
	}

	// Control: the pre-PLAN-100 advisory-keyed baseline whose SBOM does NOT contain the
	// package. The same advisory is undiscoverable -> heartbeat. If this earnest-runs, the
	// fixture is not exercising the circularity and the test proves nothing.
	narrow := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base"}).
		AddPackage(report.Package{Ecosystem: "Go", Name: "example.com/inadvisory", Version: "v1.0.0"}).
		WithProvenance(report.Provenance{CommitSHA: "base", AdvisoryCursor: ""}).
		Build()
	narrowStore := &memStore{state: &statestore.State{Report: &narrow, SBOM: narrow.SBOM, Cursor: ""}}
	osv2 := &inventoryAwareOSV{targetPkg: nonAdvisory, targetAdvisory: newAdvisory}
	res2, err := RunCVEWatch(context.Background(), narrowStore, osv2, CVEWatchRequest{
		Subject:  Subject{Repo: "r", ResolvedCommit: "base"},
		Codebase: assessment.CodebaseRef{Repo: "r"},
	})
	if err != nil {
		t.Fatalf("control RunCVEWatch: %v", err)
	}
	if !res2.Heartbeat {
		t.Fatalf("control must heartbeat: the advisory-keyed SBOM cannot discover the package; got new=%v", res2.NewAdvisories)
	}
}

// --- C6: the build-context clause is explicitly declared unimplemented --------------

// TestPRInherit_DisclosesBuildContextUnimplemented asserts §8 checkbox 12's second
// clause is disclosed as unimplemented on the inherited fast path (C6), as a QUIET
// inherent_limit so it does not assert anything about verdicts. An undisclosed
// unimplemented half would be a silent inheritance — the failure C3/C6 exist for.
func TestPRInherit_DisclosesBuildContextUnimplemented_C6(t *testing.T) {
	store, baseline := seedBaseline(t)
	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject: Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		PRSBOM:  baseline.SBOM,
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	var note *report.PartialityNote
	for i := range res.Report.Partiality {
		if res.Report.Partiality[i].Reason == report.ReasonBuildContextNotCompared {
			note = &res.Report.Partiality[i]
		}
	}
	if note == nil {
		t.Fatalf("inherited Report must disclose build-context-not-compared (C6); notes=%+v", res.Report.Partiality)
	}
	if note.EffectiveClass() != report.PartialityInherentLimit {
		t.Fatalf("build-context disclosure must be a quiet inherent_limit, got %q", note.EffectiveClass())
	}
}

// --- C7: measured cost of the widened diff vs the old version-only one --------------

func benchSBOM(n int) report.SBOM {
	pkgs := make([]report.Package, n)
	var rels []report.Relationship
	for i := 0; i < n; i++ {
		name := "example.com/dep" + itoa(i)
		pkgs[i] = report.Package{Ecosystem: "Go", Name: name, Version: "v1.0.0", PURL: "pkg:golang/" + name + "@v1.0.0", Direct: i%3 == 0}
		if i > 0 {
			rels = append(rels, report.Relationship{Parent: pkgs[i-1].Key(), Child: pkgs[i].Key()})
		}
	}
	return report.SBOM{Packages: pkgs, Relationships: rels}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

func BenchmarkChangedPackages_Relationship(b *testing.B) {
	base := benchSBOM(300)
	head := benchSBOM(300)
	head.Packages[150].Direct = !head.Packages[150].Direct
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = changedPackages(base, head)
	}
}

func BenchmarkVersionOnly_Legacy(b *testing.B) {
	base := benchSBOM(300)
	head := benchSBOM(300)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = versionOnlyChanged(base, head)
	}
}
