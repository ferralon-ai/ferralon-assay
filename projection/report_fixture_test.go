package projection_test

import (
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// fixtureReport builds a representative Report covering all three deterministic
// verdicts. It is the single Report all three Report-driven projector tests
// (OpenVEX, SARIF, HTML) project from — proving the one-Report acceptance criterion.
func fixtureReport() report.Report {
	ts := time.Date(2026, 6, 15, 12, 30, 0, 0, time.UTC)
	pkgText := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"}
	pkgNet := report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0", PURL: "pkg:golang/golang.org/x/net@v0.17.0"}
	pkgYaml := report.Package{Ecosystem: "Go", Name: "gopkg.in/yaml.v2", Version: "v2.4.0"}

	return report.NewBuilder(report.Subject{
		Repo:           "github.com/example/widget",
		Revision:       "main",
		ResolvedCommit: "abc123def456",
	}).
		AddPackages(pkgText, pkgNet, pkgYaml).
		Disqualified(
			report.Advisory{ID: "GO-2021-0001", Source: "osv", Aliases: []string{"CVE-2021-0001"}},
			&pkgText,
			verdict.BasisVersionNotAffected,
			"resolved v0.3.7 is below the first affected version v0.3.8",
		).
		NotExploitable(
			report.Advisory{ID: "GO-2022-0002", Source: "osv"},
			&pkgYaml,
			verdict.BasisSymbolAbsent,
			"the vulnerable Unmarshal path is not present in the built artifact",
		).
		ReachableCandidate(
			report.Advisory{ID: "CVE-2023-39325", Source: "nvd", Aliases: []string{"GHSA-4374-p667-p6c8"}},
			&pkgNet,
			"net/http.(*Server).Serve → golang.org/x/net/http2.(*serverConn).serve",
			"an HTTP/2 handler path reaches the advisory symbol",
		).
		WithProvenance(report.Provenance{
			AnalyzerVersion: "ferralon-assay v0.2.0",
			AdvisoryCursor:  "osv:2026-06-15",
			Timestamp:       ts,
		}).
		Build()
}

// fixtureReportWithPriority returns a Report with a fully-populated Priority signal
// (EPSS + KEV), a reachability grade, an entry point, and call frames — used to
// assert the projection renders all intel fields without panicking.
func fixtureReportWithPriority() report.Report {
	pkgNet := report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0", PURL: "pkg:golang/golang.org/x/net@v0.17.0"}
	p := &report.Priority{
		EPSSScore:      0.940,
		EPSSPercentile: 0.98,
		KEVListed:      true,
		KEVDateAdded:   "2024-01-15",
		Snapshot:       "2026-06-15",
	}
	entry := &report.EntryPoint{
		Symbol:               "net/http.HandlerFunc",
		Kind:                 "http_route",
		AttackerControllable: true,
	}
	frames := []report.CallFrame{
		{Symbol: "net/http.HandlerFunc", File: "server.go", Line: 42},
		{Symbol: "golang.org/x/net/http2.(*serverConn).serve", File: "h2.go", Line: 100},
	}
	f := report.AdvisoryFinding{
		Advisory: report.Advisory{ID: "CVE-2024-0001", Source: "nvd"},
		Package:  &pkgNet,
		Verdict:  report.VerdictReachableCandidate,
		Evidence: report.EvidenceSummary{
			Grade:         report.GradeAttackerTainted,
			ReachablePath: "net/http.HandlerFunc → golang.org/x/net/http2.(*serverConn).serve",
			Detail:        "attacker-tainted path reaches the advisory symbol",
			EntryPoint:    entry,
			CallPath:      frames,
		},
		Priority: p,
	}
	// Also include one finding WITHOUT priority to test the nil-Priority path.
	f2 := report.AdvisoryFinding{
		Advisory: report.Advisory{ID: "GO-2021-NOPRI", Source: "osv"},
		Package:  &pkgNet,
		Verdict:  report.VerdictNotExploitable,
		Evidence: report.EvidenceSummary{Detail: "symbol absent"},
	}
	return report.NewBuilder(report.Subject{
		Repo:           "github.com/example/widget",
		ResolvedCommit: "deadbeef",
	}).
		AddPackage(pkgNet).
		AddFinding(f).
		AddFinding(f2).
		WithProvenance(report.Provenance{
			AnalyzerVersion: "ferralon-assay v0.2.0",
			Timestamp:       time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		}).
		Build()
}

// fixtureReportEmpty is a valid Report with no advisories (clean scan) — used to
// prove the projectors handle the empty case (HTML empty-state, etc.).
func fixtureReportEmpty() report.Report {
	return report.NewBuilder(report.Subject{
		Repo:           "github.com/example/clean",
		ResolvedCommit: "0000000",
	}).
		WithProvenance(report.Provenance{
			AnalyzerVersion: "ferralon-assay v0.2.0",
			Timestamp:       time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC),
		}).
		Build()
}
