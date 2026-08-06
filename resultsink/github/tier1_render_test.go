package github_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// gradedFixtureResult builds a Report whose reachable candidates exercise every
// rendering branch: an attacker-tainted graded candidate with EPSS + KEV intel and
// an attacker-controllable entry point; a control-flow-only graded candidate with
// EPSS but no KEV; and an ungraded candidate with no matched intel (nil Priority).
func gradedFixtureResult() resultsink.Result {
	goPkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	npmPkg := report.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	gemPkg := report.Package{Ecosystem: "RubyGems", Name: "nokogiri", Version: "1.13.0"}

	r := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		ReachableCandidateGraded(
			report.Advisory{ID: "CVE-2021-44228", Source: "nvd"}, &goPkg,
			report.GradeAttackerTainted,
			&report.EntryPoint{Symbol: "GET /api/ingest", Kind: "http_route", AttackerControllable: true},
			nil,
			"net/http.Handler → x/text.Vuln", "candidate").
		ReachableCandidateGraded(
			report.Advisory{ID: "CVE-2022-42003", Source: "nvd"}, &npmPkg,
			report.GradeControlFlowOnly,
			&report.EntryPoint{Symbol: "main.batch", Kind: "cli", AttackerControllable: false},
			nil,
			"app.batch → lodash.template", "candidate").
		ReachableCandidate(
			report.Advisory{ID: "CVE-2020-0001", Source: "nvd"}, &gemPkg,
			"app.parse → nokogiri.Parse", "candidate").
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()

	// Attach intel out-of-band so the renderer's nil-vs-present branches are covered.
	for i := range r.Advisories {
		switch r.Advisories[i].Advisory.ID {
		case "CVE-2021-44228":
			r.Advisories[i].Priority = &report.Priority{
				EPSSScore: 0.974, EPSSPercentile: 0.999,
				KEVListed: true, KEVDateAdded: "2021-12-10", Snapshot: "2026-06-01",
			}
		case "CVE-2022-42003":
			r.Advisories[i].Priority = &report.Priority{
				EPSSScore: 0.014, EPSSPercentile: 0.68, Snapshot: "2026-06-01",
			}
			// CVE-2020-0001 deliberately left with nil Priority (no matched intel).
		}
	}

	return resultsink.Result{Report: r}
}

// renderedTier1Body drives the fixture through the sticky-comment sink and returns the
// single rendered comment body — the shared renderTier1Body output, exercised exactly
// as the live PR-comment and pinned-Issue surfaces render it.
func renderedTier1Body(t *testing.T, res resultsink.Result) string {
	t.Helper()
	mock := newMockGitHub()
	srv := mock.server(t)
	sink := ghsink.NewTier1PRComment(prWriteEnv(srv.URL, 7), srv.Client())
	if err := sink.Publish(context.Background(), res); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := len(mock.commentsByIssue[7]); got != 1 {
		t.Fatalf("want 1 sticky comment, got %d", got)
	}
	return mock.commentsByIssue[7][0].Body
}

// TestTier1Body_RendersGradeEPSSKEV asserts the enhanced candidate table surfaces the
// reachability grade, the entry point (with attacker-controllable marker), EPSS
// score+percentile, the KEV-listed marker with date, and the snapshot footer — plus
// the inv. 5 framing that none of these is an exploitability verdict.
func TestTier1Body_RendersGradeEPSSKEV(t *testing.T) {
	body := renderedTier1Body(t, gradedFixtureResult())

	for _, want := range []string{
		// New table header columns.
		"| Advisory | Package | Grade | Entry point | EPSS | KEV | Candidate path |",
		// Attacker-tainted candidate: grade, entry point + controllability, EPSS, KEV.
		"`attacker_tainted`",
		"`GET /api/ingest` (http_route) — attacker-controllable",
		"0.974 (p100)",
		"KEV-listed (2021-12-10)",
		// Control-flow-only candidate: grade, EPSS, non-attacker entry.
		"`control_flow_only`",
		"`main.batch` (cli)",
		"0.014 (p68)",
		// Snapshot footer (once).
		"EPSS/KEV intel snapshot: 2026-06-01",
		// inv. 5 framing must be present.
		"evidence strength, not a verdict",
		"in the wild",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered body missing %q\n---\n%s", want, body)
		}
	}

	// The intel-context note must be present exactly once (it is a per-table footer note,
	// not per-finding).
	if n := strings.Count(body, "EPSS/KEV intel snapshot:"); n != 1 {
		t.Errorf("want snapshot line exactly once, got %d\n%s", n, body)
	}

	// inv. 5: the body must never assert exploitability or surface forbidden verdicts.
	for _, forbidden := range []string{"affected", "::error", "Exploitable", "Affected"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("inv.5 violation: body contains %q", forbidden)
		}
	}
}

// TestTier1Body_OmitsAbsentIntel asserts that a candidate with nil Priority shows no
// EPSS/KEV text (em-dashes), and that an EPSS-only candidate prints no KEV marker —
// the renderer never fabricates "not KEV" or a zero EPSS for unmatched intel.
func TestTier1Body_OmitsAbsentIntel(t *testing.T) {
	body := renderedTier1Body(t, gradedFixtureResult())

	// The ungraded, nil-Priority candidate row.
	var nilRow string
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "CVE-2020-0001") {
			nilRow = line
			break
		}
	}
	if nilRow == "" {
		t.Fatalf("nil-Priority candidate row not found\n%s", body)
	}
	// Its Grade, Entry point, EPSS, and KEV cells must all be em-dashes (no fabricated
	// 0.000 EPSS, no grade, no entry point, no KEV).
	if strings.Contains(nilRow, "0.000") {
		t.Errorf("nil-Priority row fabricated an EPSS score: %q", nilRow)
	}
	if strings.Contains(nilRow, "KEV") {
		t.Errorf("nil-Priority row fabricated a KEV marker: %q", nilRow)
	}

	// The body must never print a "not KEV" / "not listed" style negation for the
	// EPSS-only candidate.
	for _, forbidden := range []string{"not KEV", "not listed", "Not KEV", "KEV: no"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("renderer printed a KEV negation %q; absent KEV must render nothing", forbidden)
		}
	}
	// Exactly one KEV-listed marker (only the attacker-tainted candidate is listed).
	if n := strings.Count(body, "KEV-listed"); n != 1 {
		t.Errorf("want exactly 1 KEV-listed marker, got %d\n%s", n, body)
	}
}

// TestTier1Body_NoCandidates_NoIntelSection asserts that a report with no reachable
// candidates renders neither the candidate table nor the EPSS/KEV note/footer.
func TestTier1Body_NoCandidates_NoIntelSection(t *testing.T) {
	r := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		Disqualified(report.Advisory{ID: "CVE-2020-0001", Source: "nvd"}, nil, verdict.BasisVersionNotAffected, "version below first affected").
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
	body := renderedTier1Body(t, resultsink.Result{Report: r})

	for _, absent := range []string{"### Reachable candidates", "EPSS/KEV intel snapshot:", "| Grade |"} {
		if strings.Contains(body, absent) {
			t.Errorf("no-candidate body should not contain %q\n%s", absent, body)
		}
	}
}
