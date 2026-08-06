// report_html.go
//
// Single self-contained, file://-safe HTML projection of a report.Report.
//
// Design constraints (RFC plan, Phase 2 item 4):
//   - ONE file. All CSS and JS are inlined; there are NO external references
//     (<link>, <script src>, <img src=http…>) and NO runtime fetch/XHR. The page
//     renders correctly when opened directly from disk via a file:// URL.
//   - The report data is embedded once as canonical JSON inside an inline
//     <script type="application/json" id="report-data"> block. The JS reads it
//     from the DOM (document.getElementById(...).textContent) and renders the
//     summary, the per-advisory table, and SVG charts. The JSON is the single
//     source of truth; the HTML is a view over it.
//   - SVG charts are drawn by the inline JS (no chart library, no canvas image
//     decode) so the file is portable and dependency-free.
//
// The JSON is the SAME neutral Report (so a consumer can extract it from the page
// and re-project), guaranteeing all three projectors are driven from one Report.
package projection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// ReportHTMLDataElementID is the id of the inline <script type="application/json">
// element that carries the canonical Report JSON. Tests and downstream extractors
// key on it.
const ReportHTMLDataElementID = "report-data"

// reportHTMLView is the precomputed, render-ready view the template consumes. The
// raw Report JSON travels in DataJSON; the rest are convenience fields so the Go
// template stays declarative and the file is correct even with JS disabled.
type reportHTMLView struct {
	Title       string
	Brand       string
	Repo        string
	Revision    string
	Commit      string
	Analyzer    string
	GeneratedAt string
	Total       int
	Counts      reportHTMLCounts
	Findings    []reportHTMLFinding
	// Limits are the scan's coverage disclosures (Report.Partiality). WithheldCount is how many
	// advisories a limit removed from the findings table entirely — the v1 shape, zero on a
	// report this analyzer produced. UndeterminedCount is how many findings carry no verdict;
	// together they gate the "not assessed" heading, which must read as a first-class result and
	// not as a footnote: an advisory unassessed for honesty that renders nowhere is
	// indistinguishable from one that was never in the corpus.
	Limits            []reportHTMLLimit
	WithheldCount     int
	UndeterminedCount int
	DataJSON          template.JS
}

// NotAssessedCount is the number of advisories the disclosed limits left without a verdict, by
// either shape: an undetermined row (v2) or an id a limit withheld from the table (an upgraded v1
// document, or another producer's report). The two are disjoint by construction — ProjectReportHTML
// drops a withheld id that is also a row — so the sum never double-counts one advisory.
func (v reportHTMLView) NotAssessedCount() int { return v.UndeterminedCount + v.WithheldCount }

type reportHTMLLimit struct {
	Reason     string
	Label      string
	Ecosystem  string
	Advisories []string
	// Withheld is true when this limit suppressed verdicts (Advisories is non-empty), which is a
	// materially different disclosure from a limit that merely narrowed coverage.
	Withheld bool
}

type reportHTMLCounts struct {
	Disqualified       int
	NotExploitable     int
	ReachableCandidate int
	Undetermined       int
}

type reportHTMLFinding struct {
	ID       string
	Source   string
	Aliases  string
	Package  string
	Verdict  string
	Label    string
	Severity string // CSS class suffix: ok | info | candidate | notassessed
	Detail   string
	Path     string
	// UndeterminedReason is the machine-readable code behind a "not assessed" row, rendered
	// alongside the human sentence so a reader can match it to the coverage limit above and to
	// the same code in the SARIF and JSON.
	UndeterminedReason string
	// Priority / intel fields — zero values mean "not present"; template gates on HasPriority.
	HasPriority    bool
	EPSSScore      float64
	EPSSPercentile float64
	EPSSPct        int // EPSSPercentile as an integer percentile (0–100) for display
	KEVListed      bool
	KEVDateAdded   string
	IntelSnapshot  string
	// Reachability-grade and entry-point fields — gated on HasGrade / HasEntryPoint.
	HasGrade             bool
	Grade                string // "attacker_tainted" | "control_flow_only"
	GradeLabel           string // human-readable badge text
	HasEntryPoint        bool
	EntrySymbol          string
	EntryKind            string
	AttackerControllable bool
	// CallPath structured frames.
	CallFrames []reportHTMLFrame
}

type reportHTMLFrame struct {
	Symbol string
	File   string
	Line   int
}

// ProjectReportHTML renders a report.Report into a single self-contained,
// file://-safe HTML document. The returned bytes are a complete HTML page.
func ProjectReportHTML(r report.Report) ([]byte, error) {
	if r.SchemaVersion == "" {
		return nil, fmt.Errorf("projection/report_html: report has no schema version")
	}

	// Canonical, indented JSON of the exact Report — the page's single source of truth.
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("projection/report_html: marshal report: %w", err)
	}
	// Defang any "</script" sequence so the JSON cannot break out of its <script>
	// container. JSON marshalling escapes "<"/">" as </> already (Go's
	// default), but be explicit and robust regardless of upstream changes.
	safe := bytes.ReplaceAll(data, []byte("</"), []byte("<\\/"))

	view := reportHTMLView{
		Title:       brand.ReportTitle(),
		Brand:       brand.Name,
		Repo:        r.Subject.Repo,
		Revision:    r.Subject.Revision,
		Commit:      r.Subject.ResolvedCommit,
		Analyzer:    r.Provenance.AnalyzerVersion,
		GeneratedAt: r.Provenance.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"),
		Total:       len(r.Advisories),
		DataJSON:    template.JS(safe), //nolint:gosec // defanged above; html/template would double-escape JSON in a <script type=application/json> block.
	}

	for i := range r.Advisories {
		f := r.Advisories[i]
		view.Findings = append(view.Findings, reportHTMLFindingFrom(f))
		switch f.Verdict {
		case report.VerdictDisqualified:
			view.Counts.Disqualified++
		case report.VerdictNotExploitable:
			view.Counts.NotExploitable++
		case report.VerdictReachableCandidate:
			view.Counts.ReachableCandidate++
		case report.VerdictUndetermined:
			view.Counts.Undetermined++
			view.UndeterminedCount++
		}
	}

	rowIDs := make(map[string]struct{}, len(r.Advisories))
	for i := range r.Advisories {
		rowIDs[r.Advisories[i].Advisory.ID] = struct{}{}
	}
	for _, n := range r.Partiality {
		// An id present in the findings table is not also listed under its limit: it already
		// renders as an undetermined row, and naming it twice would double the "not assessed"
		// count a reader sees. Only an id the limit removed from the table entirely (the v1
		// shape) needs the limit to name it.
		withheld := make([]string, 0, len(n.Advisories))
		for _, id := range n.Advisories {
			if _, ok := rowIDs[id]; ok {
				continue
			}
			withheld = append(withheld, id)
		}
		view.Limits = append(view.Limits, reportHTMLLimit{
			Reason:     n.Reason,
			Label:      reportHTMLLimitLabel(n.Reason),
			Ecosystem:  n.Ecosystem,
			Advisories: withheld,
			Withheld:   len(withheld) > 0,
		})
		view.WithheldCount += len(withheld)
	}

	var buf bytes.Buffer
	if err := reportHTMLTemplate.Execute(&buf, view); err != nil {
		return nil, fmt.Errorf("projection/report_html: render: %w", err)
	}
	return buf.Bytes(), nil
}

// MarshalReportHTML is the convenience alias matching the Marshal* family. It is
// identical to ProjectReportHTML (the HTML page is already the serialized form).
func MarshalReportHTML(r report.Report) ([]byte, error) {
	return ProjectReportHTML(r)
}

func reportHTMLFindingFrom(f report.AdvisoryFinding) reportHTMLFinding {
	var pkg string
	if f.Package != nil {
		pkg = fmt.Sprintf("%s:%s@%s", f.Package.Ecosystem, f.Package.Name, f.Package.Version)
	}
	var aliases string
	if len(f.Advisory.Aliases) > 0 {
		for i, a := range f.Advisory.Aliases {
			if i > 0 {
				aliases += ", "
			}
			aliases += a
		}
	}
	label, severity := reportHTMLLabel(f.Verdict)
	out := reportHTMLFinding{
		ID:                 f.Advisory.ID,
		Source:             f.Advisory.Source,
		Aliases:            aliases,
		Package:            pkg,
		Verdict:            string(f.Verdict),
		Label:              label,
		Severity:           severity,
		Detail:             f.Evidence.Detail,
		Path:               f.Evidence.ReachablePath,
		UndeterminedReason: f.UndeterminedReason,
	}

	// Priority: EPSS/KEV exploitation-likelihood context from the pinned intel snapshot.
	// These are NEVER exploitability claims for this codebase (inv. 5).
	if f.Priority != nil {
		out.HasPriority = true
		out.EPSSScore = f.Priority.EPSSScore
		out.EPSSPercentile = f.Priority.EPSSPercentile
		out.EPSSPct = int(f.Priority.EPSSPercentile * 100)
		out.KEVListed = f.Priority.KEVListed
		out.KEVDateAdded = f.Priority.KEVDateAdded
		out.IntelSnapshot = f.Priority.Snapshot
	}

	// Reachability grade — evidence-strength context for a reachable_candidate.
	if f.Evidence.Grade != "" {
		out.HasGrade = true
		out.Grade = string(f.Evidence.Grade)
		out.GradeLabel = reportHTMLGradeLabel(f.Evidence.Grade)
	}

	// Entry point — ingress at the path head.
	if f.Evidence.EntryPoint != nil {
		out.HasEntryPoint = true
		out.EntrySymbol = f.Evidence.EntryPoint.Symbol
		out.EntryKind = f.Evidence.EntryPoint.Kind
		out.AttackerControllable = f.Evidence.EntryPoint.AttackerControllable
	}

	// Call frames — structured ingress→sink path.
	if len(f.Evidence.CallPath) > 0 {
		out.CallFrames = make([]reportHTMLFrame, len(f.Evidence.CallPath))
		for i, fr := range f.Evidence.CallPath {
			out.CallFrames[i] = reportHTMLFrame{
				Symbol: fr.Symbol,
				File:   fr.File,
				Line:   fr.Line,
			}
		}
	}

	return out
}

// reportHTMLLimitLabel renders a human sentence for a partiality reason code. The vocabulary is OPEN
// (report.PartialityNote.Reason), so an unrecognized code falls through to the raw code rather than
// being dropped — dropping it restores the silent-clean-scan failure the disclosure exists to prevent.
func reportHTMLLimitLabel(reason string) string {
	switch reason {
	case report.ReasonGoToolchainUnresolved:
		return "The Go toolchain this codebase builds with could not be determined, so advisories that " +
			"affect the toolchain itself were not assessed."
	case report.ReasonGoToolchainNotScanned:
		return "Advisories affecting the Go toolchain were not assessed against this codebase's own " +
			"toolchain version, so no verdict is reported for them."
	case report.ReasonAnalysisDidNotRun:
		return "The analysis steps that would locate this advisory's code in what this repository " +
			"builds did not run, so no verdict is reported for it."
	default:
		return reason
	}
}

func reportHTMLGradeLabel(g report.ReachabilityGrade) string {
	switch g {
	case report.GradeAttackerTainted:
		return "attacker-tainted candidate"
	case report.GradeControlFlowOnly:
		return "control-flow only"
	default:
		return string(g)
	}
}

func reportHTMLLabel(v report.Verdict) (label, severity string) {
	switch v {
	case report.VerdictDisqualified:
		return "Disqualified", "ok"
	case report.VerdictNotExploitable:
		return "Not exploitable", "info"
	case report.VerdictReachableCandidate:
		return "Reachable candidate", "candidate"
	case report.VerdictUndetermined:
		// Its own badge class, sharing the coverage-limits panel's colour. Deliberately not
		// "info" (the not_exploitable class): a reader scanning badge colours must not read an
		// unassessed advisory as a grounded-safe one.
		return "Not assessed", "notassessed"
	default:
		return string(v), "info"
	}
}
