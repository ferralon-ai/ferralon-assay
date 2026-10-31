package trigger

import (
	"context"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// These tests pin PR re-analysis to one invariant: a verdict is never inherited across a changed
// package, and an advisory is never left without a row. Each table's last row is the control: a
// package that genuinely did not change still inherits.

// baselineDetail marks the baseline's own row, so a test can tell an inherited row from a fresh one.
const baselineDetail = "baseline row, inherited"

func lodash(v string) report.Package {
	return report.Package{Ecosystem: "npm", Name: "lodash", Version: v, PURL: "pkg:npm/lodash@" + v}
}

// TestChangedPackages_MultipleCopies_Issue307: tracker#307. One name installed at several versions
// is compared over every copy, so a PR that moves one copy while another stays put is a change and
// does not take the inherit fast path.
func TestChangedPackages_MultipleCopies_Issue307(t *testing.T) {
	cases := []struct {
		name      string
		base      []report.Package
		head      []report.Package
		inherited bool
	}{
		{"one copy moved, the last stayed (the #307 repro)",
			[]report.Package{lodash("4.17.10"), lodash("4.17.21")}, []report.Package{lodash("4.17.4"), lodash("4.17.21")}, false},
		{"a copy removed, the last stayed",
			[]report.Package{lodash("4.17.10"), lodash("4.17.21")}, []report.Package{lodash("4.17.21")}, false},
		{"a copy added ahead of the last",
			[]report.Package{lodash("4.17.21")}, []report.Package{lodash("4.17.4"), lodash("4.17.21")}, false},
		{"control: the same copies",
			[]report.Package{lodash("4.17.10"), lodash("4.17.21")}, []report.Package{lodash("4.17.10"), lodash("4.17.21")}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
				AddPackages(tc.base...).
				WithProvenance(report.Provenance{CommitSHA: "base-sha"}).
				Build()
			store := &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM}}
			res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
				Subject: Subject{Repo: "r", ResolvedCommit: "pr-sha"},
				PRSBOM:  report.SBOM{Packages: tc.head},
			})
			if err != nil {
				t.Fatalf("RunPRInherit: %v", err)
			}
			if res.Inherited != tc.inherited {
				t.Fatalf("Inherited = %v, want %v (changed = %q)", res.Inherited, tc.inherited, res.ChangedPackages)
			}
			if want := []string{"npm\x00lodash"}; !tc.inherited && !slices.Equal(res.ChangedPackages, want) {
				t.Fatalf("ChangedPackages = %q, want %q", res.ChangedPackages, want)
			}
		})
	}
}

// TestChangedPackages_CopyOrderIsNotAChange: the copies of one name are a multiset, so listing the
// same copies in another order changes nothing.
func TestChangedPackages_CopyOrderIsNotAChange(t *testing.T) {
	base := report.SBOM{Packages: []report.Package{lodash("4.17.10"), lodash("4.17.21")}}
	head := report.SBOM{Packages: []report.Package{lodash("4.17.21"), lodash("4.17.10")}}
	if changed := changedPackages(base, head); len(changed) != 0 {
		t.Fatalf("changed = %q, want none", changed)
	}
}

// twoPackageAdvisory affects golang.org/x/text and golang.org/x/net. Select-by-target picks x/text
// when the head carries it, and records x/net beside it. Every version these tests use is outside
// both ranges, so a fresh row is a settled disqualification rather than an undetermined one, which
// would replace the baseline's row whether or not a package changed.
var twoPackageAdvisory = assessment.VulnRef{ID: "FERRALON-TEST-308", Source: "corpus"}

type twoPackageSource struct{}

func (twoPackageSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	if id != twoPackageAdvisory.ID {
		return pipeline.NewTableSource().Lookup(id)
	}
	affected := func(module string) pipeline.AffectedPackage {
		return pipeline.AffectedPackage{
			Module: module, PURL: "pkg:golang/" + module,
			AffectedRanges: []pipeline.Range{{Introduced: "v9.0.0", Fixed: "v9.1.0"}},
			Symbols:        []string{module + ".Vulnerable"},
		}
	}
	return pipeline.AdvisoryFacts{
		Module:           "golang.org/x/text",
		PURL:             "pkg:golang/golang.org/x/text",
		AffectedRanges:   []pipeline.Range{{Introduced: "v9.0.0", Fixed: "v9.1.0"}},
		Symbols:          []string{"golang.org/x/text.Vulnerable"},
		AffectedPackages: []pipeline.AffectedPackage{affected("golang.org/x/text"), affected("golang.org/x/net")},
		Provenance:       pipeline.Provenance{Source: "test", TrustTier: pipeline.TrustFirstParty},
	}, true
}

// prMergeRun runs PR re-analysis of one advisory over a head whose go.mod is goMod and whose SBOM
// is head, against a baseline holding base and, when withRow, a row for the advisory.
func prMergeRun(t *testing.T, adv assessment.VulnRef, base, head []report.Package, goMod string, withRow bool) *PRInheritResult {
	t.Helper()
	b := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).AddPackages(base...)
	if withRow {
		pkg := base[0]
		b.NotExploitable(report.Advisory{ID: adv.ID, Source: adv.Source}, &pkg, "vulnerable_symbol_absent", baselineDetail)
	}
	baseline := b.WithProvenance(report.Provenance{CommitSHA: "base-sha"}).Build()
	store := &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM}}
	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase:   assessment.CodebaseRef{Repo: "r", Revision: "main"},
		PRSBOM:     report.SBOM{Packages: head},
		Advisories: []assessment.VulnRef{adv},
		AssessOptions: []pipeline.AssessOption{
			pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, goMod), lang: "go"}),
			pipeline.WithPlugin(refutingGoPlugin{inventory: plugin.Complete()}),
			pipeline.WithAdvisorySource(twoPackageSource{}),
		},
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	if res.Inherited {
		t.Fatal("took the inherit fast path; every case here changes a package")
	}
	return res
}

// rowsFor returns the report's rows for the advisory id.
func rowsFor(rep *report.Report, id string) []report.AdvisoryFinding {
	var out []report.AdvisoryFinding
	for _, f := range rep.Advisories {
		if f.Advisory.ID == id {
			out = append(out, f)
		}
	}
	return out
}

func goPkg(name, v string) report.Package {
	return report.Package{Ecosystem: "Go", Name: name, Version: v}
}

func goModRequiring(reqs ...string) string {
	s := "module example.com/target\n\ngo 1.21\n"
	for _, r := range reqs {
		s += "\nrequire " + r + "\n"
	}
	return s
}

// TestReanalyzeSlice_AnotherAffectedPackageChanged_Issue308: tracker#308. Whether the baseline's row
// stands is judged over every package the advisory affects, not only the one the head selected: a
// changed x/net replaces the baseline's row even though the selected x/text did not move, and so
// does a selected package the head no longer carries at all.
func TestReanalyzeSlice_AnotherAffectedPackageChanged_Issue308(t *testing.T) {
	text, other := goPkg("golang.org/x/text", "v0.3.6"), goPkg("example.org/other", "v1.0.0")
	cases := []struct {
		name      string
		base      []report.Package
		head      []report.Package
		goMod     string
		inherited bool
	}{
		{"selected package unchanged, the other affected package changed (the #308 repro)",
			[]report.Package{text, goPkg("golang.org/x/net", "v0.1.0")},
			[]report.Package{text, goPkg("golang.org/x/net", "v0.2.0")},
			goModRequiring("golang.org/x/text v0.3.6", "golang.org/x/net v0.2.0"), false},
		{"the head no longer carries any affected package",
			[]report.Package{text},
			[]report.Package{other},
			goModRequiring("example.org/other v1.0.0"), false},
		{"control: no affected package changed",
			[]report.Package{text, goPkg("golang.org/x/net", "v0.1.0")},
			[]report.Package{text, goPkg("golang.org/x/net", "v0.1.0"), other},
			goModRequiring("golang.org/x/text v0.3.6", "golang.org/x/net v0.1.0", "example.org/other v1.0.0"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := prMergeRun(t, twoPackageAdvisory, tc.base, tc.head, tc.goMod, true)
			rows := rowsFor(res.Report, twoPackageAdvisory.ID)
			if len(rows) != 1 {
				t.Fatalf("%d rows for %s, want 1: %+v", len(rows), twoPackageAdvisory.ID, rows)
			}
			if inherited := rows[0].Evidence.Detail == baselineDetail; inherited != tc.inherited {
				t.Fatalf("inherited the baseline's row = %v, want %v (row: %s, %q; changed = %q)",
					inherited, tc.inherited, rows[0].Verdict, rows[0].Evidence.Detail, res.ChangedPackages)
			}
		})
	}
}

// TestReanalyzeSlice_NewAdvisoryWithNoBaselineRow_Issue309: tracker#309. An advisory the baseline
// holds no row for gets its fresh row whatever its package — unchanged, or none at all — since
// there is nothing to inherit in its place.
func TestReanalyzeSlice_NewAdvisoryWithNoBaselineRow_Issue309(t *testing.T) {
	text, other := goPkg("golang.org/x/text", "v0.3.6"), goPkg("example.org/other", "v1.0.0")
	cases := []struct {
		name    string
		adv     assessment.VulnRef
		base    []report.Package
		head    []report.Package
		goMod   string
		withRow bool
		want    string // "fresh" or "inherited"
	}{
		{"no baseline row, package unchanged (the #309 repro)", wiringAdvisory,
			[]report.Package{text}, []report.Package{text, other},
			goModRequiring("golang.org/x/text v0.3.6", "example.org/other v1.0.0"), false, "fresh"},
		{"no baseline row, no package selected", twoPackageAdvisory,
			[]report.Package{goPkg("example.org/kept", "v1.0.0")}, []report.Package{goPkg("example.org/kept", "v1.0.0"), other},
			goModRequiring("example.org/kept v1.0.0", "example.org/other v1.0.0"), false, "fresh"},
		{"control: a baseline row, package unchanged", wiringAdvisory,
			[]report.Package{text}, []report.Package{text, other},
			goModRequiring("golang.org/x/text v0.3.6", "example.org/other v1.0.0"), true, "inherited"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := prMergeRun(t, tc.adv, tc.base, tc.head, tc.goMod, tc.withRow)
			rows := rowsFor(res.Report, tc.adv.ID)
			if len(rows) != 1 {
				t.Fatalf("%d rows for %s, want 1: %+v", len(rows), tc.adv.ID, rows)
			}
			got := "fresh"
			if rows[0].Evidence.Detail == baselineDetail {
				got = "inherited"
			}
			if got != tc.want {
				t.Fatalf("row is %s, want %s (row: %s, %q; changed = %q)", got, tc.want, rows[0].Verdict, rows[0].Evidence.Detail, res.ChangedPackages)
			}
		})
	}
}

// Copies of one name that differ only in whether the build installs them are still a multiset:
// listing them in another order changes nothing.
func TestChangedPackages_InstalledCopyOrderIsNotAChange(t *testing.T) {
	left := lodash("4.17.21")
	left.NotInstalled = true
	base := report.SBOM{Packages: []report.Package{lodash("4.17.21"), left}}
	head := report.SBOM{Packages: []report.Package{left, lodash("4.17.21")}}
	if changed := changedPackages(base, head); len(changed) != 0 {
		t.Fatalf("changed = %q, want none", changed)
	}
}
