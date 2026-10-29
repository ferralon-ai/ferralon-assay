package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// File names inside one scan job's result directory.
const (
	fileMeta   = "meta.json"
	fileReport = "report.json"
)

// Meta is meta.json, which the workflow's scan job writes beside report.json whatever happened to
// the scan: which build scanned the repository, how the scan step ended, and how long it took.
type Meta struct {
	Repo        string `json:"repo"`
	Policy      string `json:"policy"`
	AssayCommit string `json:"assay_commit"`
	// Outcome is the scan step's outcome as GitHub Actions reports it: success, failure, cancelled
	// or skipped.
	Outcome string `json:"outcome"`
	// ExitCode is the scanner's exit code; nil when the scanner never exited (it never started, or
	// the job was stopped first).
	ExitCode *int `json:"exit_code"`
	// DurationSeconds is how long the scanner ran; nil when it never exited.
	DurationSeconds *int64 `json:"duration_seconds"`
}

// Failure kinds. Every kind fails the repository and so the run.
const (
	KindNoResult       = "no_result"
	KindScanFailed     = "scan_failed"
	KindNoReport       = "no_report"
	KindMalformed      = "malformed_report"
	KindTruncated      = "scan_truncated"
	KindUngroundedNE   = "ungrounded_not_exploitable"
	KindUngroundedDisq = "ungrounded_disqualified"
)

// Failure is one reason a repository failed the floor.
type Failure struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	// Findings names the offending findings, when the failure is about findings.
	Findings []string `json:"findings,omitempty"`
}

// ReasonCount is one undetermined_reason code and how many findings carry it.
type ReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// RepoResult is one repository's line of the floor summary.
type RepoResult struct {
	Repo            string `json:"repo"`
	Language        string `json:"language"`
	Ref             string `json:"ref,omitempty"`
	AssayCommit     string `json:"assay_commit,omitempty"`
	Policy          string `json:"policy,omitempty"`
	AnalyzerVersion string `json:"analyzer_version,omitempty"`
	ScannedCommit   string `json:"scanned_commit,omitempty"`
	DurationSeconds *int64 `json:"duration_seconds"`
	// Verdicts counts the report's findings per verdict; every verdict is present, zero included.
	// Nil when there is no readable report.
	Verdicts map[report.Verdict]int `json:"verdicts"`
	// TopUndetermined is the most frequent undetermined_reason codes, at most topReasons of them.
	TopUndetermined []ReasonCount `json:"top_undetermined_reasons"`
	ScanTruncated   bool          `json:"scan_truncated"`
	// Unverifiable names the disqualified findings whose report carries no version or symbol basis
	// to check. They are counted, never failed: an intake disqualification records that no
	// comparison was made.
	Unverifiable []string  `json:"unverifiable,omitempty"`
	Pass         bool      `json:"pass"`
	Failures     []Failure `json:"failures,omitempty"`
}

// topReasons is how many undetermined_reason codes a repository's line names.
const topReasons = 3

// verdictOrder is every verdict a report may carry, in display order.
var verdictOrder = []report.Verdict{
	report.VerdictReachableCandidate,
	report.VerdictMaliciousPresent,
	report.VerdictNotExploitable,
	report.VerdictDisqualified,
	report.VerdictUndetermined,
}

// grounds classifies a finding's grounds for the floor.
type grounds int

const (
	// groundsNotChecked: the verdict asserts no refutation, so it needs no grounds.
	groundsNotChecked grounds = iota
	// groundsPresent: the finding names a basis that grounds its verdict.
	groundsPresent
	// groundsMissing: a refutation with no basis, or a basis that cannot ground its verdict.
	groundsMissing
	// groundsUnverifiable: a disqualification whose report records no version or symbol basis.
	groundsUnverifiable
)

// groundsOf decides whether a finding's refutation is grounded. The authoritative field is the
// finding's evidence.basis (report.EvidenceSummary.Basis): it is the only grounds field report.json
// carries. verdict.Verdict's non_exploitable_basis and reasoned_grounds belong to the service-tier
// verdict, which a report.json never holds, so they cannot ground a report finding.
//
//   - not_exploitable needs one of the four refutation bases (verdict.NonExploitableBasis).
//   - disqualified on the version or symbol axis carries that axis's basis
//     (version_not_in_affected_range, vulnerable_symbol_absent); one with no basis is an intake
//     disqualification (advisory_ecosystem_mismatch, no_manifest_entry), where no comparison was made
//     and there is nothing to check; any other basis cannot ground a disqualification.
func groundsOf(f report.AdvisoryFinding) grounds {
	switch f.Verdict {
	case report.VerdictNotExploitable:
		switch f.Evidence.Basis {
		case verdict.BasisVersionNotAffected, verdict.BasisSymbolAbsent,
			verdict.BasisSymbolUnreachable, verdict.BasisStaticRefutation:
			return groundsPresent
		default:
			return groundsMissing
		}
	case report.VerdictDisqualified:
		switch f.Evidence.Basis {
		case verdict.BasisVersionNotAffected, verdict.BasisSymbolAbsent:
			return groundsPresent
		case verdict.BasisNone:
			return groundsUnverifiable
		default:
			return groundsMissing
		}
	default:
		return groundsNotChecked
	}
}

// findingLabel names a finding in the summary: its advisory id and, when it has one, its package.
func findingLabel(f report.AdvisoryFinding) string {
	if f.Package == nil {
		return f.Advisory.ID
	}
	return f.Advisory.ID + " (" + f.Package.Label() + ")"
}

// decodeReport reads a report.json the way Assay's own readers do: decode, upgrade an older schema,
// then validate. Any error makes the report malformed.
func decodeReport(data []byte) (report.Report, error) {
	var r report.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return report.Report{}, err
	}
	r, err := report.Upgrade(r)
	if err != nil {
		return report.Report{}, err
	}
	if err := r.Validate(); err != nil {
		return report.Report{}, err
	}
	return r, nil
}

// assessReport fills res from a decoded report: verdict counts, undetermined reasons, truncation,
// and a failure for each class of ungrounded refutation.
func assessReport(res *RepoResult, r report.Report) {
	res.AnalyzerVersion = r.Provenance.AnalyzerVersion
	res.ScannedCommit = r.Subject.ResolvedCommit
	res.Verdicts = map[report.Verdict]int{}
	for _, v := range verdictOrder {
		res.Verdicts[v] = 0
	}
	reasons := map[string]int{}
	var ungroundedNE, ungroundedDisq []string
	for _, f := range r.Advisories {
		res.Verdicts[f.Verdict]++
		if f.Verdict == report.VerdictUndetermined {
			reasons[f.UndeterminedReason]++
		}
		switch groundsOf(f) {
		case groundsMissing:
			if f.Verdict == report.VerdictNotExploitable {
				ungroundedNE = append(ungroundedNE, findingLabel(f))
			} else {
				ungroundedDisq = append(ungroundedDisq, findingLabel(f))
			}
		case groundsUnverifiable:
			res.Unverifiable = append(res.Unverifiable, findingLabel(f))
		}
	}
	res.TopUndetermined = topReasonCounts(reasons, topReasons)
	if len(ungroundedNE) > 0 {
		res.Failures = append(res.Failures, Failure{
			Kind:     KindUngroundedNE,
			Detail:   fmt.Sprintf("%d not_exploitable without grounds", len(ungroundedNE)),
			Findings: ungroundedNE,
		})
	}
	if len(ungroundedDisq) > 0 {
		res.Failures = append(res.Failures, Failure{
			Kind:     KindUngroundedDisq,
			Detail:   fmt.Sprintf("%d disqualified on a basis that does not ground a disqualification", len(ungroundedDisq)),
			Findings: ungroundedDisq,
		})
	}
	for _, n := range r.Partiality {
		if n.Reason == report.ReasonScanCutShort {
			res.ScanTruncated = true
			detail := "the scan stopped at its time limit before assessing every advisory"
			if n.Detail != "" {
				detail += ": " + n.Detail
			}
			res.Failures = append(res.Failures, Failure{Kind: KindTruncated, Detail: detail})
			break
		}
	}
}

// topReasonCounts returns the n most frequent reasons, most frequent first, ties by name.
func topReasonCounts(counts map[string]int, n int) []ReasonCount {
	out := make([]ReasonCount, 0, len(counts))
	for r, c := range counts {
		out = append(out, ReasonCount{Reason: r, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Reason < out[j].Reason
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// scanFailure describes how a scan step that did not succeed ended, or "" when it succeeded.
func scanFailure(m Meta) string {
	switch {
	case m.Outcome == "cancelled":
		return "the scan job was stopped before the scan finished (its timeout or a cancellation)"
	case m.ExitCode == nil:
		return fmt.Sprintf("the scan step ended %q before the scanner exited", m.Outcome)
	case *m.ExitCode != 0:
		return fmt.Sprintf("the scanner exited %d", *m.ExitCode)
	case m.Outcome != "success":
		return fmt.Sprintf("the scan step ended %q", m.Outcome)
	default:
		return ""
	}
}

// scanResult is what one scan job left behind: its meta.json and, when it wrote one, its report.
type scanResult struct {
	meta      Meta
	report    []byte
	hasReport bool
}

// evaluate judges one target from what its scan job left behind; sr is nil when the job left
// nothing (it failed before writing meta.json, or never ran).
func evaluate(t Target, policy string, sr *scanResult) RepoResult {
	res := RepoResult{Repo: t.Repo, Language: t.Language, Ref: t.Ref, Policy: policy}
	if sr == nil {
		res.Failures = []Failure{{Kind: KindNoResult,
			Detail: "the scan job left no result: it failed before the scan, timed out or was cancelled"}}
		return res
	}
	res.AssayCommit = sr.meta.AssayCommit
	if sr.meta.Policy != "" {
		res.Policy = sr.meta.Policy
	}
	res.DurationSeconds = sr.meta.DurationSeconds
	if msg := scanFailure(sr.meta); msg != "" {
		res.Failures = append(res.Failures, Failure{Kind: KindScanFailed, Detail: msg})
	}
	switch {
	case !sr.hasReport:
		if len(res.Failures) == 0 {
			res.Failures = append(res.Failures, Failure{Kind: KindNoReport, Detail: "the scan wrote no report.json"})
		}
	default:
		r, err := decodeReport(sr.report)
		if err != nil {
			res.Failures = append(res.Failures, Failure{Kind: KindMalformed, Detail: err.Error()})
		} else {
			assessReport(&res, r)
		}
	}
	res.Pass = len(res.Failures) == 0
	return res
}

// readResults reads every scan job's result directory under dir: each directory holding a
// meta.json, keyed by the meta's repo.
func readResults(dir string) (map[string]*scanResult, error) {
	out := map[string]*scanResult{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != fileMeta {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var m Meta
		if err := json.Unmarshal(data, &m); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if m.Repo == "" {
			return fmt.Errorf("%s: no repo", path)
		}
		if _, dup := out[m.Repo]; dup {
			return fmt.Errorf("%s: a second result for %s", path, m.Repo)
		}
		sr := &scanResult{meta: m}
		rep, err := os.ReadFile(filepath.Join(filepath.Dir(path), fileReport))
		switch {
		case err == nil:
			sr.report, sr.hasReport = rep, true
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}
		out[m.Repo] = sr
		return nil
	})
	return out, err
}
