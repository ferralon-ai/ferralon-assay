// gotoolchain_withhold_test.go
//
// A Go toolchain/stdlib advisory the scan could not adjudicate gets NO VERDICT.
// tegron.report.v1 expressed that by withholding the row and disclosing at scan level, because
// v1's verdict set had no cell for it; tegron.report.v2 expresses it as a first-class
// `undetermined` row plus the same scan-level limit. These tests assert the v2 shape — the row is
// present, the reason is machine-readable, and no refutation basis rides on it.
//
// The claim being removed was not a soft label. trigger.finding's `default:` arm emitted
// `not_exploitable` with basis `vulnerable_symbol_absent`, which report_vex.go maps to OpenVEX
// `status: not_affected, justification: vulnerable_code_not_present` — a machine-readable,
// standards-conformant attestation of safety, on a fact the scanner never established (the empty
// path set came from govulncheck running against the SCANNER's Go, not the subject's).
//
// These tests run the REAL baseline path (buildBaselineReport → assess → the whole S1–S6 pipeline)
// over a real go.mod on disk. Nothing is hand-seeded into any artifact.
package trigger

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/goanalysis"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// goManifestPlugin's BuildManifest is the REAL goanalysis.BuildManifest (a genuine modfile parse), so
// the subject's toolchain floor is produced from the go.mod on disk rather than injected.
//
// Its analysis ops deliberately return EMPTY rather than StubPlugin's canned results, because
// StubPlugin fabricates a reachable path (scip:stub#main → scip:stub#Foo → scip:vuln#Vulnerable) for
// every advisory it is asked about, which makes every finding a reachable_candidate and puts the
// `default:` arm of finding() out of reach. Empty results reproduce the shape the real Go lane
// actually produces for a stdlib advisory on a newer scanner toolchain — govulncheck flags nothing, no
// path forms, no candidate pair is written — which is the exact state that emitted the unestablished
// `not_exploitable`. Fixture homogeneity in the stub is what let that shape go untested.
type goManifestPlugin struct{ plugin.StubPlugin }

func (goManifestPlugin) Language() string { return "go" }

func (goManifestPlugin) BuildManifest(ctx context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	return goanalysis.BuildManifest(ctx, req)
}

func (goManifestPlugin) IndexSymbols(context.Context, plugin.IndexSymbolsRequest) (plugin.SymbolIndexResult, error) {
	return plugin.SymbolIndexResult{Partiality: plugin.Complete()}, nil
}

func (goManifestPlugin) ResolveDependencySymbols(context.Context, plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	return plugin.SymbolResolutionResult{Partiality: plugin.Complete()}, nil
}

func (goManifestPlugin) CallGraph(context.Context, plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{Partiality: plugin.Complete(), Algorithm: "vta"}, nil
}

func (goManifestPlugin) FindIngresses(context.Context, plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	return plugin.IngressResult{Partiality: plugin.Complete()}, nil
}

func (goManifestPlugin) Reachability(context.Context, plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	return plugin.ReachabilityResult{Partiality: plugin.Complete()}, nil
}

// fixedCheckout is a hermetic checkout returning a fixed build dir + language (no git, no network).
type fixedCheckout struct{ dir, lang string }

func (c fixedCheckout) Fetch(context.Context, string, string) (string, string, error) {
	return c.dir, c.lang, nil
}

// the four advisories whose disposition this change decides: three carry the explicit go-toolchain
// version scheme, GO-2021-0264 is a pkg:golang/stdlib advisory whose scheme derives to gomod.
var goToolchainCorpus = []assessment.VulnRef{
	{ID: "CVE-2023-39325", Source: "corpus"},
	{ID: "CVE-2023-45283", Source: "corpus"},
	{ID: "CVE-2024-24790", Source: "corpus"},
	{ID: "GO-2021-0264", Source: "corpus"},
}

func writeGoMod(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return dir
}

// runGoBaseline runs the real baseline over the given advisories against a real go.mod tree.
func runGoBaseline(t *testing.T, goMod string, advisories []assessment.VulnRef, opts ...pipeline.AssessOption) *report.Report {
	t.Helper()
	buildDir := writeGoMod(t, goMod)
	opts = append([]pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: buildDir, lang: "go"}),
		pipeline.WithPlugin(goManifestPlugin{}),
	}, opts...)
	rep, err := buildBaselineReport(context.Background(), BaselineRequest{
		Subject:       Subject{Repo: "example.com/target", Revision: "main", ResolvedCommit: "deadbeef"},
		Codebase:      assessment.CodebaseRef{Repo: "example.com/target", Revision: "main"},
		Advisories:    advisories,
		AssessOptions: opts,
	})
	if err != nil {
		t.Fatalf("buildBaselineReport: %v", err)
	}
	return rep
}

func verdictByID(r *report.Report) map[string]report.Verdict {
	out := make(map[string]report.Verdict, len(r.Advisories))
	for _, f := range r.Advisories {
		out[f.Advisory.ID] = f.Verdict
	}
	return out
}

// withheldByReason indexes the ids a scan-level note WITHHELD from advisories[]. Under v2 a
// producer never withholds, so a non-empty result from a freshly built report is a defect: it
// means an advisory is named in a note and missing from the rows. It stays as an assertion
// target for exactly that, and for reading an upgraded v1 document's residue.
func withheldByReason(r *report.Report) map[string][]string {
	out := make(map[string][]string, len(r.Partiality))
	for _, n := range r.Partiality {
		if len(n.Advisories) > 0 {
			out[n.Reason] = append(out[n.Reason], n.Advisories...)
		}
	}
	return out
}

// undeterminedByReason indexes the report's `undetermined` rows by reason code, ids sorted. This
// is the v2 successor to withheldByReason: the same four advisories, now first-class rows.
func undeterminedByReason(r *report.Report) map[string][]string {
	out := make(map[string][]string)
	for _, f := range r.Advisories {
		if f.Verdict != report.VerdictUndetermined {
			continue
		}
		out[f.UndeterminedReason] = append(out[f.UndeterminedReason], f.Advisory.ID)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// assertUndetermined checks the whole per-row contract for one advisory: the verdict, the reason
// code, and the two things that make it a non-verdict rather than a weak verdict — no refutation
// basis and no reachable path.
func assertUndetermined(t *testing.T, r *report.Report, id, wantReason string) {
	t.Helper()
	for _, f := range r.Advisories {
		if f.Advisory.ID != id {
			continue
		}
		if f.Verdict != report.VerdictUndetermined {
			t.Errorf("%s verdict = %q, want %q", id, f.Verdict, report.VerdictUndetermined)
		}
		if f.UndeterminedReason != wantReason {
			t.Errorf("%s undetermined_reason = %q, want %q", id, f.UndeterminedReason, wantReason)
		}
		if f.Evidence.Basis != "" {
			t.Errorf("%s carries basis %q on an undetermined verdict — a basis is what makes a refutation a claim", id, f.Evidence.Basis)
		}
		if f.Evidence.ReachablePath != "" {
			t.Errorf("%s carries reachable_path %q on an undetermined verdict", id, f.Evidence.ReachablePath)
		}
		return
	}
	t.Errorf("%s absent from advisories[] — v2 reports it as an undetermined row, it is not withheld", id)
}

// assertNoNotAffected is the consequence that opened the cycle, asserted at the wire: whatever
// else the OpenVEX document says, it must never attest not_affected for an advisory whose verdict
// the scan did not establish. `under_investigation` with no justification is the honest status.
func assertNoNotAffected(t *testing.T, r *report.Report, ids ...string) {
	t.Helper()
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	doc, err := projection.ProjectReportVEX(*r)
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	seen := make(map[string]struct{}, len(ids))
	for _, stmt := range doc.Statements {
		if _, ok := want[stmt.Vulnerability.ID]; !ok {
			continue
		}
		seen[stmt.Vulnerability.ID] = struct{}{}
		if stmt.Status != projection.VEXStatusUnderInvestigation {
			t.Errorf("OpenVEX %s status = %q, want %q — the scan established no verdict for it",
				stmt.Vulnerability.ID, stmt.Status, projection.VEXStatusUnderInvestigation)
		}
		if stmt.Justification != "" {
			t.Errorf("OpenVEX %s carries justification %q — an unestablished advisory has no grounds to justify",
				stmt.Vulnerability.ID, stmt.Justification)
		}
	}
	for id := range want {
		if _, ok := seen[id]; !ok {
			t.Errorf("OpenVEX has no statement for %s — v2 attests it under_investigation rather than omitting it", id)
		}
	}
}

// TestBaseline_UnadjudicableToolchainAdvisoriesAreUndetermined is the headline assertion: on a
// subject whose toolchain floor is INSIDE the affected ranges, none of the four can be disqualified
// and none has a reachable path, so all four are `undetermined` rows under one disclosed limit —
// and no `not_exploitable` row survives for any of them.
//
// The v1 predecessor asserted advisories[] was EMPTY. That the same four advisories are now present
// and countable is the entire value of the bump: `len(advisories)` is the number evaluated again.
func TestBaseline_UnadjudicableToolchainAdvisoriesAreUndetermined(t *testing.T) {
	// go 1.20 ⇒ floor go1.20.0, inside the 1.20.x range of all three backports.
	rep := runGoBaseline(t, "module example.com/target\n\ngo 1.20\n", goToolchainCorpus)

	want := []string{"CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790", "GO-2021-0264"}
	if len(rep.Advisories) != len(want) {
		t.Fatalf("advisories[] = %+v, want %d rows: every advisory evaluated appears, undetermined included", rep.Advisories, len(want))
	}
	got := undeterminedByReason(rep)[report.ReasonGoToolchainNotScanned]
	if len(got) != len(want) {
		t.Fatalf("undetermined under %s = %v, want %v", report.ReasonGoToolchainNotScanned, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("undetermined[%d] = %q, want %q", i, got[i], want[i])
		}
		assertUndetermined(t, rep, want[i], report.ReasonGoToolchainNotScanned)
	}

	// The scan-level limit still renders, and names no ids: the rows carry them now, and repeating
	// them here would make every surface count the same advisory twice.
	var notScanned int
	for _, n := range rep.Partiality {
		if n.Reason == report.ReasonGoToolchainNotScanned {
			notScanned++
			if n.Ecosystem != "Go" {
				t.Errorf("ecosystem = %q, want Go", n.Ecosystem)
			}
			if len(n.Advisories) != 0 {
				t.Errorf("limit names %v; under v2 the ids live in the rows, not in the note", n.Advisories)
			}
		}
	}
	if notScanned != 1 {
		t.Errorf("got %d %s notes, want exactly 1 — the notes must MERGE by (reason, ecosystem)", notScanned, report.ReasonGoToolchainNotScanned)
	}
}

// TestBaseline_UndeterminedAdvisoriesEmitNoOpenVEXNotAffected is the consequence that matters most,
// and it must still fall out of the VERDICT rather than out of projector code: report_vex.go's
// default arm already returns under_investigation, so an undetermined row cannot reach the wire as
// a safety attestation. A projector edit here would have been the smell — it would mean the honest
// verdict still had a path to not_affected.
func TestBaseline_UndeterminedAdvisoriesEmitNoOpenVEXNotAffected(t *testing.T) {
	rep := runGoBaseline(t, "module example.com/target\n\ngo 1.20\n", goToolchainCorpus)
	assertNoNotAffected(t, rep, "CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790", "GO-2021-0264")
}

// TestBaseline_DisqualifiedToolchainAdvisoryIsReported is the other half of the story, and the reason
// M3 had to land first. On a subject whose toolchain floor is past every branch fix, the version axis
// DERIVES a not-affected. That is a stronger and honestly grounded claim than the one M2 withdraws, so
// it is reported as a first-class disqualified finding and is NOT withheld.
func TestBaseline_DisqualifiedToolchainAdvisoryIsReported(t *testing.T) {
	// go 1.23 ⇒ floor go1.23.0, at or past every fix in all three backports.
	rep := runGoBaseline(t, "module example.com/target\n\ngo 1.23\n", goToolchainCorpus)

	verdicts := verdictByID(rep)
	for _, id := range []string{"CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790"} {
		if verdicts[id] != report.VerdictDisqualified {
			t.Errorf("%s verdict = %q, want %q — the lit version axis proves the floor is past every branch fix", id, verdicts[id], report.VerdictDisqualified)
		}
	}
	// GO-2021-0264 declares no affected range at all, so the version axis has nothing to adjudicate
	// no matter which toolchain the subject uses — it stays undetermined.
	assertUndetermined(t, rep, "GO-2021-0264", report.ReasonGoToolchainNotScanned)
	if got := undeterminedByReason(rep)[report.ReasonGoToolchainNotScanned]; len(got) != 1 || got[0] != "GO-2021-0264" {
		t.Errorf("undetermined = %v, want [GO-2021-0264] only", got)
	}
}

// TestBaseline_ShippedActionSurfaceDisposition pins what a real Action run now produces, because that
// is the disposition anyone reading a customer report will see and it should not have to be inferred.
//
// action.yml observes `go env GOVERSION` on the runner BEFORE installing the scanner's toolchain (M1),
// but that observation only participates when the caller asserts trust-observed-go (ruling 7). So there
// are TWO shipped dispositions and the difference between them is the whole point of the gate.
//
// This is the OPTED-IN one, which the in-repo dogfood workflows use truthfully: the exact fact is past
// every fix in all three backports, so the version axis derives real disqualifications — the strongest
// honest outcome, and the one M2's withholding must not eat. GO-2021-0264 has no affected range to
// compare against, so no toolchain version can settle it and it stays withheld.
func TestBaseline_ShippedActionSurfaceDisposition_TrustOptedIn(t *testing.T) {
	rep := runGoBaseline(t, "module example.com/target\n\ngo 1.20\n", goToolchainCorpus,
		pipeline.WithSubjectToolchain("", "go1.26.4", true))

	verdicts := verdictByID(rep)
	for _, id := range []string{"CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790"} {
		if verdicts[id] != report.VerdictDisqualified {
			t.Errorf("%s = %q, want disqualified on an exact go1.26.4 observation", id, verdicts[id])
		}
	}
	if got := undeterminedByReason(rep)[report.ReasonGoToolchainNotScanned]; len(got) != 1 || got[0] != "GO-2021-0264" {
		t.Errorf("undetermined = %v, want [GO-2021-0264] — it declares no affected range, so no toolchain version can settle it", got)
	}
	assertUndetermined(t, rep, "GO-2021-0264", report.ReasonGoToolchainNotScanned)
}

// TestBaseline_ShippedActionSurfaceDisposition_NoConfigDefault is the disposition a customer who merges
// the scaffolded workflow and configures NOTHING actually gets, which is the case reviewer-07's major
// was about. The Action still samples the runner's Go — a recent go1.26.4 on any hosted runner — but
// with trust withheld it does not participate, so the fact rests on the go1.20.0 floor. That floor is
// inside every one of the three backports' ranges, so nothing is disqualified and all four advisories
// are undetermined with disclosure.
//
// The contrast with the opted-in test above is the safety property: identical inputs, and the untrusted
// run declines to assert a not-affected where the trusted run asserts three. Under the pre-ruling
// behavior this run produced those three disqualifications from a version that described the runner
// image rather than the subject — an OpenVEX not_affected for a build still exposed.
func TestBaseline_ShippedActionSurfaceDisposition_NoConfigDefault(t *testing.T) {
	rep := runGoBaseline(t, "module example.com/target\n\ngo 1.20\n", goToolchainCorpus,
		pipeline.WithSubjectToolchain("", "go1.26.4", false))

	got := undeterminedByReason(rep)[report.ReasonGoToolchainNotScanned]
	want := []string{"CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790", "GO-2021-0264"}
	if len(got) != len(want) {
		t.Fatalf("undetermined under %s = %v, want all four %v — an untrusted observation establishes nothing, and the go1.20.0 floor is inside every affected range",
			report.ReasonGoToolchainNotScanned, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("undetermined[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	for _, id := range want {
		if v := verdictByID(rep)[id]; v == report.VerdictNotExploitable || v == report.VerdictDisqualified {
			t.Errorf("%s = %q on the no-config default — an untrusted runner observation must not license a refutation", id, v)
		}
	}

	// The reason code must be not_scanned, not unresolved: a floor WAS resolved and adjudicated here,
	// and only reachability is missing. Collapsing the two would lose that distinction.
	if got := undeterminedByReason(rep)[report.ReasonGoToolchainUnresolved]; len(got) != 0 {
		t.Errorf("undetermined under %s = %v, want none — the go.mod floor resolved, so this is not the unresolved state", report.ReasonGoToolchainUnresolved, got)
	}

	// And no OpenVEX not_affected reaches the wire for any of them.
	assertNoNotAffected(t, rep, want...)
}

// TestBaseline_UnresolvedToolchainUsesTheWeakerReasonCode separates the two disclosure codes. With no
// version directive at all the version axis had nothing either, which is a different and weaker state
// than "we resolved a floor, adjudicated it, and only reachability is missing".
func TestBaseline_UnresolvedToolchainUsesTheWeakerReasonCode(t *testing.T) {
	rep := runGoBaseline(t, "module example.com/target\n", goToolchainCorpus)

	byReason := undeterminedByReason(rep)
	if got := len(byReason[report.ReasonGoToolchainUnresolved]); got != 4 {
		t.Errorf("undetermined under %s = %v, want all four (no directive ⇒ no fact)", report.ReasonGoToolchainUnresolved, byReason[report.ReasonGoToolchainUnresolved])
	}
	if got := byReason[report.ReasonGoToolchainNotScanned]; len(got) != 0 {
		t.Errorf("undetermined under %s = %v, want none", report.ReasonGoToolchainNotScanned, got)
	}
	assertUndetermined(t, rep, "CVE-2023-39325", report.ReasonGoToolchainUnresolved)
}

// TestBaseline_ModuleAdvisoriesAreUnaffected is the blast-radius fence. This work must change
// exactly the unestablished toolchain claims and nothing else: a real module dependency advisory
// keeps its verdict, its SBOM package, and its OpenVEX statement.
func TestBaseline_ModuleAdvisoriesAreUnaffected(t *testing.T) {
	rep := runGoBaseline(t,
		"module example.com/target\n\ngo 1.20\n\nrequire golang.org/x/text v0.3.6\n",
		[]assessment.VulnRef{{ID: "GO-2021-0113", Source: "corpus"}})

	if len(rep.Advisories) != 1 {
		t.Fatalf("advisories[] = %+v, want exactly the module finding", rep.Advisories)
	}
	f := rep.Advisories[0]
	if f.Advisory.ID != "GO-2021-0113" {
		t.Fatalf("advisory = %q, want GO-2021-0113", f.Advisory.ID)
	}
	if f.Package == nil || f.Package.Name != "golang.org/x/text" || f.Package.Version != "v0.3.6" {
		t.Errorf("package = %+v, want golang.org/x/text@v0.3.6 — a module advisory still carries its SBOM coordinate", f.Package)
	}
	for _, n := range rep.Partiality {
		if len(n.Advisories) > 0 {
			t.Errorf("unexpected withholding disclosure %+v on a module-only scan", n)
		}
	}
}

// TestBaseline_ToolchainAdvisoryCarriesNoSBOMPackage guards a coordinate that does not exist. When the
// adjudicated element is the toolchain, resolved_version is a go1.x.y toolchain release while the
// advisory's top-level module is a real module path; pairing them would put
// `golang.org/x/net@go1.23.0` in the SBOM and in the OpenVEX product id.
func TestBaseline_ToolchainAdvisoryCarriesNoSBOMPackage(t *testing.T) {
	rep := runGoBaseline(t, "module example.com/target\n\ngo 1.23\n",
		[]assessment.VulnRef{{ID: "CVE-2023-39325", Source: "corpus"}})

	for _, p := range rep.SBOM.Packages {
		t.Errorf("SBOM carries %s:%s@%s for a toolchain advisory — the Go toolchain is not a dependency package", p.Ecosystem, p.Name, p.Version)
	}
	if len(rep.Advisories) != 1 {
		t.Fatalf("advisories[] = %+v, want the disqualified finding", rep.Advisories)
	}
	if rep.Advisories[0].Package != nil {
		t.Errorf("finding package = %+v, want nil", rep.Advisories[0].Package)
	}
}
