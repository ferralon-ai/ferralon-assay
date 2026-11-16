package trigger

import (
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_ScopedVerdict: when the library view's refutation is withheld (library_escape) and the
// lane's program view rules the advisory out, the row keeps the library view's verdict and carries a
// not_exploitable scoped to the shipped binaries; the OpenVEX statement for it names the binary as
// its product, and SARIF carries the scope. A program view of another package, or none, adds nothing.
func TestFinding_ScopedVerdict(t *testing.T) {
	withheld := func(view *plugin.ProgramView) groundsFixture {
		fx := netNotReached()
		fx.reach.Refutation = nil
		fx.reach.ProgramView = view
		fx.footprint = []string{plugin.PartialReasonLibraryEscape}
		return fx
	}
	view := func(pkg string) *plugin.ProgramView {
		return &plugin.ProgramView{
			Module:   "example.com/m",
			Binaries: []string{"cmd/tool"},
			Refutation: plugin.Refutation{
				Basis:   plugin.RefutationAnalyzerSymbolNotReached,
				Package: pkg,
				Detail:  "started from the main and init of cmd/tool only: govulncheck found no call path",
			},
		}
	}
	for _, tc := range []struct {
		name string
		fx   groundsFixture
		want bool
	}{
		{"the program view rules it out", withheld(view("pkg:golang/golang.org/x/net")), true},
		{"no program view", withheld(nil), false},
		{"a program view of another package", withheld(view("pkg:golang/golang.org/x/text")), false},
	} {
		f := tc.fx.finding(t)
		if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != report.ReasonRefutationWithheld {
			t.Fatalf("%s: library view = %s/%q, want undetermined/refutation_withheld, unchanged", tc.name, f.Verdict, f.UndeterminedReason)
		}
		if (len(f.ScopedVerdicts) > 0) != tc.want {
			t.Fatalf("%s: scoped verdicts = %+v, want present %v", tc.name, f.ScopedVerdicts, tc.want)
		}
		if !tc.want {
			continue
		}
		sv := f.ScopedVerdicts[0]
		if sv.Verdict != report.VerdictNotExploitable || sv.Scope.Kind != report.ScopeBinaries || !slices.Equal(sv.Scope.Targets, []string{"cmd/tool"}) {
			t.Errorf("%s: scoped verdict = %+v", tc.name, sv)
		}
		r := report.Report{SchemaVersion: report.SchemaVersion, Subject: report.Subject{Repo: "example.com/m", ResolvedCommit: "abc123"}, Advisories: []report.AdvisoryFinding{f}}
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: Validate: %v", tc.name, err)
		}
		doc, err := projection.ProjectReportVEX(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Statements) != 2 {
			t.Fatalf("%s: %d statements, want the library view's and the binary's", tc.name, len(doc.Statements))
		}
		lib, bin := doc.Statements[0], doc.Statements[1]
		if lib.Status != projection.VEXStatusUnderInvestigation || lib.Products[0].ID != "pkg:golang/golang.org/x/net@v0.1.0" {
			t.Errorf("%s: library statement = %+v, want the module's under_investigation", tc.name, lib)
		}
		if bin.Status != projection.VEXStatusNotAffected || bin.Justification != projection.VEXJustNotInExecutePath ||
			bin.Products[0].ID != "pkg:golang/example.com/m@abc123?binary=cmd/tool" ||
			bin.Products[0].Subcomponents[0].ID != "pkg:golang/golang.org/x/net@v0.1.0" ||
			!strings.Contains(bin.ImpactStatement, "Not reachable from the shipped binary `cmd/tool`; still possible when this module is imported as a library.") {
			t.Errorf("%s: binary statement = %+v", tc.name, bin)
		}
		sarif, err := projection.ProjectReportSARIF(r)
		if err != nil {
			t.Fatal(err)
		}
		res := sarif.Runs[0].Results[0]
		scoped, _ := res.Properties.Scanner["scoped_verdicts"].([]report.ScopedVerdict)
		if len(scoped) != 1 || !slices.Equal(scoped[0].Scope.Targets, []string{"cmd/tool"}) || !strings.Contains(res.Message.Text, "shipped binary `cmd/tool`") {
			t.Errorf("%s: SARIF scoped_verdicts = %+v, message %q", tc.name, scoped, res.Message.Text)
		}
	}
}
