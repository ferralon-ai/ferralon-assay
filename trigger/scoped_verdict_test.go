package trigger

import (
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_ScopedVerdict: when the library view's refutation is withheld (library_escape), or the
// library view holds a path, and the lane's program view rules the advisory out, the row keeps the
// library view's verdict and carries a not_exploitable scoped to the shipped binaries; the OpenVEX
// statement for it names the binary as its product, and SARIF carries the scope. A program view of
// another package, or none, adds nothing, and neither row kind carries one past a did-not-run limit,
// which holds a library not_exploitable back too. A candidate whose recorded path enters at the binary
// carries none either, as does one whose entry id names its package ambiguously (an alias receiver's
// package-qualified name in the descriptor); one entering elsewhere, another module included, still does.
func TestFinding_ScopedVerdict(t *testing.T) {
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
	net := view("pkg:golang/golang.org/x/net")
	withheld := func(view *plugin.ProgramView, footprint ...string) groundsFixture {
		fx := netNotReached()
		fx.reach.Refutation = nil
		fx.reach.ProgramView = view
		fx.footprint = append([]string{plugin.PartialReasonLibraryEscape}, footprint...)
		return fx
	}
	candidate := func(view *plugin.ProgramView, footprint ...string) groundsFixture {
		fx := netNotReached()
		fx.reach.Refutation = nil
		fx.reach.ProgramView = view
		fx.candidate = true
		fx.footprint = footprint
		return fx
	}
	// sym is a symbol as the Go lane records it: the SCIP id alone, Package empty.
	sym := func(pkg, name string) plugin.Symbol {
		return plugin.Symbol{Name: name, SCIP: "scip-go gomod example.com/m v1.0.0 " + pkg + "/" + name + "()."}
	}
	// entering is a reachable candidate the program view rules out, whose recorded path starts in entry,
	// as the call-graph fallback records one.
	entering := func(entry plugin.Symbol) groundsFixture {
		fx := candidate(net)
		fx.reach.Paths = []plugin.ReachPath{{
			Sink:  sym("golang.org/x/net/html", "Parse"),
			Trace: []plugin.Symbol{entry, sym("golang.org/x/net/html", "Parse")},
		}}
		return fx
	}
	// scip is an entry recorded by its SCIP id alone, in module mod.
	scip := func(mod, id string) plugin.Symbol {
		return plugin.Symbol{Name: "M", SCIP: "scip-go gomod " + mod + " v1.0.0 " + id}
	}
	ingressOnly := entering(sym("example.com/m/api", "Serve"))
	ingressOnly.reach.Paths[0].Ingress = sym("example.com/m/cmd/tool", "main")
	noEntry := entering(plugin.Symbol{})
	noEntry.reach.Paths[0].Trace = nil
	for _, tc := range []struct {
		name   string
		fx     groundsFixture
		row    report.Verdict
		reason string
		want   bool
	}{
		{"the program view rules it out", withheld(net), report.VerdictUndetermined, report.ReasonRefutationWithheld, true},
		{"no program view", withheld(nil), report.VerdictUndetermined, report.ReasonRefutationWithheld, false},
		{"a program view of another package", withheld(view("pkg:golang/golang.org/x/text")), report.VerdictUndetermined, report.ReasonRefutationWithheld, false},
		{"a withheld refutation beside a step that did not run", withheld(net, plugin.PartialReasonToolFailure), report.VerdictUndetermined, report.ReasonAnalysisDidNotRun, false},
		{"a reachable candidate the program view rules out", candidate(net), report.VerdictReachableCandidate, "", true},
		{"a reachable candidate beside a step that did not run", candidate(net, plugin.PartialReasonToolFailure), report.VerdictReachableCandidate, "", false},
		{"a reachable candidate whose path enters at the binary", entering(sym("example.com/m/cmd/tool", "main")), report.VerdictReachableCandidate, "", false},
		{"a reachable candidate whose ingress is the binary", ingressOnly, report.VerdictReachableCandidate, "", false},
		{"a reachable candidate whose path enters in a library package", entering(sym("example.com/m/api", "Serve")), report.VerdictReachableCandidate, "", true},
		{"a reachable candidate whose path enters at an alias receiver's method in the binary", entering(scip("example.com/m", "example.com/m/cmd/tool/example.com/m/cmd/tool.A#M().")), report.VerdictReachableCandidate, "", false},
		{"a reachable candidate whose path enters at a method of the binary's own type", entering(scip("example.com/m", "example.com/m/cmd/tool/handler#M().")), report.VerdictReachableCandidate, "", false},
		{"a reachable candidate whose path enters in another module", entering(scip("gopkg.in/yaml.v3", "gopkg.in/yaml.v3/Decoder#Decode().")), report.VerdictReachableCandidate, "", true},
		{"a reachable candidate whose entry id cannot be read", entering(plugin.Symbol{Name: "main", SCIP: "garbled"}), report.VerdictReachableCandidate, "", false},
		{"a reachable candidate whose path records no entry", noEntry, report.VerdictReachableCandidate, "", false},
	} {
		f := tc.fx.finding(t)
		if f.Verdict != tc.row || f.UndeterminedReason != tc.reason {
			t.Fatalf("%s: library view = %s/%q, want %s/%q, unchanged", tc.name, f.Verdict, f.UndeterminedReason, tc.row, tc.reason)
		}
		if (len(f.ScopedVerdicts) > 0) != tc.want {
			t.Fatalf("%s: scoped verdicts = %+v, want present %v", tc.name, f.ScopedVerdicts, tc.want)
		}
		r := report.Report{SchemaVersion: report.SchemaVersion, Subject: report.Subject{Repo: "example.com/m", ResolvedCommit: "abc123"}, Advisories: []report.AdvisoryFinding{f}}
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: Validate: %v", tc.name, err)
		}
		doc, err := projection.ProjectReportVEX(r)
		if err != nil {
			t.Fatal(err)
		}
		if !tc.want {
			if len(doc.Statements) != 1 || doc.Statements[0].Status == projection.VEXStatusNotAffected {
				t.Errorf("%s: statements = %+v, want the library view's alone, not not_affected", tc.name, doc.Statements)
			}
			continue
		}
		sv := f.ScopedVerdicts[0]
		if sv.Verdict != report.VerdictNotExploitable || sv.Scope.Kind != report.ScopeBinaries || !slices.Equal(sv.Scope.Targets, []string{"cmd/tool"}) {
			t.Errorf("%s: scoped verdict = %+v", tc.name, sv)
		}
		if len(doc.Statements) != 2 {
			t.Fatalf("%s: %d statements, want the library view's and the binary's", tc.name, len(doc.Statements))
		}
		lib, bin := doc.Statements[0], doc.Statements[1]
		if lib.Status == projection.VEXStatusNotAffected || lib.Products[0].ID != "pkg:golang/golang.org/x/net@v0.1.0" {
			t.Errorf("%s: library statement = %+v, want the module's own, not not_affected", tc.name, lib)
		}
		if bin.Status != projection.VEXStatusNotAffected || bin.Justification != projection.VEXJustNotInExecutePath ||
			bin.Products[0].ID != "pkg:golang/example.com/m@abc123?binary=cmd%2Ftool" ||
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
