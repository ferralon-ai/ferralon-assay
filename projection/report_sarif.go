// report_sarif.go
//
// SARIF 2.1.0 projection driven by the neutral scan report.Report.
//
// This is distinct from ProjectSARIF (sarif.go), which projects a single
// Service-tier verdict.PoE. The OSS tool produces a Report (deterministic
// verdicts only); this projector maps FROM report.Verdict, never verdict.PoE.
//
// Level mapping (inv. 5 honesty — a candidate is never a proven finding):
//
//	report.VerdictReachableCandidate → "warning" (candidate; owes Prove-tier confirmation)
//	report.VerdictNotExploitable     → "note"    (grounded refutation; informational)
//	report.VerdictDisqualified       → "none"    (provably out of scope)
//	report.VerdictUndetermined       → "none" / kind "review" (requires human review)
//	report.VerdictMaliciousPresent   → "error"   (decisive: known-malicious package present)
//
// "error" was historically reserved for a proven exploitable finding the OSS tool
// cannot produce — so a reachable candidate never projects as "error". The one
// honest exception is VerdictMaliciousPresent: it is not a candidate/lean but a
// DECISIVE determination that a known-malicious package is installed at a listed
// affected version (deterministic presence, no execution claim, inv. 5), which is
// exactly what SARIF "error" means.
//
// `kind: "review"` is SARIF's own "requires human review", and `level: "none"` keeps
// an undetermined finding out of the alert count: it is visible, and it is never
// counted as something the scan found. That is the presentation an unestablished
// verdict has to have — an alert would claim a problem, and silence would claim
// safety.
package projection

import (
	"encoding/json"
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// ProjectReportSARIF converts a report.Report into a SARIF 2.1.0 log with one
// result per advisory finding. The tool driver is "ferralon-assay".
//
// The projection is deterministic (no wall-clock) and honest: a reachable
// candidate never projects as "error".
func ProjectReportSARIF(r report.Report) (*SARIFLog, error) {
	if r.SchemaVersion == "" {
		return nil, fmt.Errorf("projection/report_sarif: report has no schema version")
	}

	results := make([]SARIFResult, 0, len(r.Advisories))
	rowIDs := make(map[string]struct{}, len(r.Advisories))
	for i := range r.Advisories {
		f := r.Advisories[i]
		level, kind := reportSARIFLevelKind(f.Verdict)
		rowIDs[f.Advisory.ID] = struct{}{}

		props := map[string]any{
			"verdict": string(f.Verdict),
		}
		if f.Verdict == report.VerdictUndetermined {
			// `assessed: false` is the machine-readable half a consumer filters on; the reason
			// code is the half that says which limit produced it. Both were run/note properties
			// under v1 and are now per-result, where the advisory they concern actually is.
			props["assessed"] = false
			props["undetermined_reason"] = f.UndeterminedReason
		}
		if f.Evidence.Basis != "" {
			props["basis"] = string(f.Evidence.Basis)
		}
		if f.Evidence.Detail != "" {
			props["detail"] = f.Evidence.Detail
		}
		if f.Evidence.ReachablePath != "" {
			props["reachable_path"] = f.Evidence.ReachablePath
		}
		if f.Package != nil {
			props["package"] = fmt.Sprintf("%s:%s@%s", f.Package.Ecosystem, f.Package.Name, f.Package.Version)
		}
		if f.Advisory.Source != "" {
			props["source"] = f.Advisory.Source
		}
		if f.Evidence.Grade != "" {
			props["reachability_grade"] = string(f.Evidence.Grade)
		}
		if f.Evidence.EntryPoint != nil {
			props["entry_point"] = f.Evidence.EntryPoint.Symbol
			props["attacker_controllable"] = f.Evidence.EntryPoint.AttackerControllable
		}

		// Priority: EPSS/KEV exploitation-likelihood context from public feeds.
		// These are wild-exploitation likelihood signals — NOT exploitability claims
		// for this codebase (inv. 5). Set rank and intel properties when present.
		var rank *float64
		if f.Priority != nil {
			props["epss_score"] = f.Priority.EPSSScore
			props["epss_percentile"] = f.Priority.EPSSPercentile
			props["kev_listed"] = f.Priority.KEVListed
			if f.Priority.KEVDateAdded != "" {
				props["kev_date_added"] = f.Priority.KEVDateAdded
			}
			if f.Priority.Snapshot != "" {
				props["intel_snapshot"] = f.Priority.Snapshot
			}
			if f.Priority.KEVListed {
				existing, _ := props["tags"].([]string)
				props["tags"] = append(existing, "CISA-KEV")
			}
			// rank is 0.0–100.0 per SARIF spec; scale from 0..1 percentile.
			rv := f.Priority.EPSSPercentile * 100.0
			rank = &rv
		}

		results = append(results, SARIFResult{
			RuleID:     f.Advisory.ID,
			Level:      level,
			Kind:       kind,
			Message:    SARIFMessage{Text: reportSARIFMessage(f)},
			Locations:  reportSARIFLocations(f),
			Rank:       rank,
			Properties: &SARIFProperties{Tegron: props},
		})
	}

	results = append(results, reportSARIFPartialityResults(r)...)

	// Coverage disclosures for any advisory a limit WITHHELD from advisories[] — the v1 shape,
	// which an upgraded document no longer carries and this analyzer no longer produces. It stays
	// because a partiality note is an open contract another producer may still populate, and an
	// advisory named in a note but absent from the rows would otherwise vanish from the SARIF
	// entirely; a silently absent advisory reads exactly like one assessed and found clean.
	//
	// rowIDs is what keeps it from double-rendering: an id present as a row is already an
	// undetermined result above, with the same level and kind, so emitting it again here would
	// duplicate one advisory into two entries in a code-scanning UI.
	results = append(results, reportSARIFNotAssessed(r.Partiality, rowIDs)...)

	log := &SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:            brand.Name,
						Version:         r.Provenance.AnalyzerVersion,
						InformationURI:  brand.RepoURL,
						SemanticVersion: r.Provenance.AnalyzerVersion,
					},
				},
				Invocations: []SARIFInvocation{reportSARIFInvocation(r)},
				Results:     results,
			},
		},
	}
	return log, nil
}

// PartialCoverageRuleID is the rule a did-not-run coverage disclosure is reported
// under. It is deliberately NOT an advisory id: the result asserts nothing about any
// vulnerability, only that part of the codebase was not analyzed.
var PartialCoverageRuleID = brand.Name + "/partial-coverage"

// AnalysisLimitsRuleID is the rule an INHERENT-limit disclosure is reported under. It
// is deliberately a distinct rule id from PartialCoverageRuleID: a consumer needs to
// be able to filter one arm without the other, and dismiss-fatigue on the
// methodology rule must never blunt the did-not-run rule beside it. See
// reportSARIFPartialityResults for why this arm gets a result at all.
var AnalysisLimitsRuleID = brand.Name + "/analysis-limits"

// reportSARIFInvocation records run-level completeness. Results alone cannot carry a
// coverage limit — an empty result set is how SARIF spells "clean" — so the limits are
// also stated here, in the slot the spec provides for them, IN ADDITION to the results
// reportSARIFPartialityResults emits. Belt-and-suspenders: toolExecutionNotifications is
// not among the run properties GitHub code scanning ingests (its documented supported
// run properties are tool.driver, tool.extensions[], invocation.workingDirectory.uri and
// results[] — nothing under invocations[]), so this block is for SARIF-spec-complete
// consumers other than GitHub; GitHub-specific visibility depends entirely on results[].
//
// EVERY limit is notified here, in both arms; the notification level is what separates
// them. A did-not-run limit is a "warning": something this run normally does was not
// done. An inherent limit of static analysis is a "note": it holds for every scan, it
// is stated for completeness, and a consumer that escalates on level must not treat it
// as a condition of this run.
//
// ExecutionSuccessful stays true even when limits are disclosed: the analysis ran and
// produced valid results, it simply covered less than the whole codebase. Reporting the
// invocation as failed would tell a consumer to discard the results, which is the
// opposite of the intent — a partial scan's verdicts are real, they just cover less.
func reportSARIFInvocation(r report.Report) SARIFInvocation {
	inv := SARIFInvocation{ExecutionSuccessful: true}
	for _, n := range r.Partiality {
		level := "warning"
		if n.EffectiveClass() == report.PartialityInherentLimit {
			level = "note"
		}
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, SARIFNotification{
			Level:   level,
			Message: SARIFMessage{Text: reportSARIFPartialityText(n)},
		})
	}
	return inv
}

// reportSARIFNotAssessed renders one "not assessed" result per WITHHELD advisory id.
//
// It is deliberately a result rather than only a run property: run properties are not surfaced by
// code-scanning UIs, so a reader would never see them, and the whole point of withholding is to make
// the omission legible rather than invisible. The result asserts nothing about exploitability — no
// verdict, no basis — which is what distinguishes it from the false not_exploitable row it replaces.
func reportSARIFNotAssessed(notes []report.PartialityNote, rowIDs map[string]struct{}) []SARIFResult {
	var out []SARIFResult
	for _, n := range notes {
		for _, id := range n.Advisories {
			if _, ok := rowIDs[id]; ok {
				continue
			}
			props := map[string]any{
				"assessed":          false,
				"partiality_reason": n.Reason,
			}
			if n.Ecosystem != "" {
				props["ecosystem"] = n.Ecosystem
			}
			out = append(out, SARIFResult{
				RuleID: id,
				Level:  "none",
				Kind:   "review",
				Message: SARIFMessage{Text: fmt.Sprintf(
					"%s: NOT ASSESSED. %s did not establish a verdict for this advisory (%s), so none is reported. "+
						"This is not a statement that the codebase is unaffected.",
					id, brand.Name, n.Reason)},
				Locations:  []SARIFLocation{{PhysicalLocation: &SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: sarifFallbackURI}, Region: &SARIFRegion{StartLine: 1}}}},
				Properties: &SARIFProperties{Tegron: props},
			})
		}
	}
	return out
}

// reportSARIFPartialityResults emits one result per coverage limit, in EITHER arm.
//
// GitHub's own "SARIF support for code scanning" reference lists the run properties it
// ingests: tool.driver, tool.extensions[], invocation.workingDirectory.uri and
// results[]. invocations[].toolExecutionNotifications is not on that list — GitHub
// discards it — so a limit that lived only in the invocation block above was, in the
// sink most teams actually read (the code-scanning UI), disclosed nowhere at all: the
// log looked byte-equivalent to a clean scan. Both arms are results now, for exactly
// the same reason task 02 gave for the did-not-run arm: a SARIF log whose results are
// all "note"/"none" (or empty) renders as a clean, alert-free scan, which is the false
// all-clear a partial analysis must never produce, and toolExecutionNotifications
// cannot rescue that for this consumer.
//
// The arms stay distinguishable in a code-scanning reader in every way the format
// gives us:
//
//   - Different rule (PartialCoverageRuleID vs AnalysisLimitsRuleID) — filterable
//     independently, and the id itself reads "analysis-limits" (methodology), not
//     "partial-coverage" (something this run skipped).
//   - Different level: "warning" (did-not-run) vs "note" (inherent limit) — the
//     lowest severity SARIF defines, sorted last, styled least urgently.
//   - Different, arm-specific prose (reportSARIFPartialityText): the inherent-limit
//     message states plainly that it "holds for every run" and "no step of this run
//     was skipped", so a reader of the message text alone — not just the level frame —
//     can tell disclosure from finding.
//   - No security-severity property on either rule, so neither is classified a
//     security result by GitHub's own model (its docs: a result is treated as a
//     "security" result only when a rule declares properties.security-severity).
//
// What this does NOT achieve, stated plainly rather than assumed: GitHub's code
// scanning model has exactly one visible surface for third-party SARIF, results[], and
// GitHub's own documentation calls every entry in it a "code scanning alert" —
// dismissible, with an open/closed state — regardless of level, kind or rule. "kind" in
// particular (fail/review/open/informational/...) is not in GitHub's documented
// supported-properties list for the result object at all, so it is not read for alert
// classification; it is set below purely for spec-completeness and for non-GitHub
// consumers. No SARIF construct this codebase can emit makes the inherent-limit arm
// literally un-alert-able in GitHub's data model while remaining visible there — the
// choice made here is the closest available approximation (lowest severity, distinct
// non-security rule, self-describing message, no code location beyond the repo root),
// not a literal satisfaction of "not an alert." See execution/13-fix-b1-b2.md.
func reportSARIFPartialityResults(r report.Report) []SARIFResult {
	if len(r.Partiality) == 0 {
		return nil
	}
	out := make([]SARIFResult, 0, len(r.Partiality))
	for _, n := range r.Partiality {
		ruleID, level, kind := PartialCoverageRuleID, "warning", "review"
		class := report.PartialityDidNotRun
		if n.EffectiveClass() == report.PartialityInherentLimit {
			ruleID, level, kind = AnalysisLimitsRuleID, "note", "informational"
			class = report.PartialityInherentLimit
		}
		props := map[string]any{
			"partiality_reason": n.Reason,
			"partiality_class":  string(class),
		}
		if n.Ecosystem != "" {
			props["ecosystem"] = n.Ecosystem
		}
		if n.Detail != "" {
			props["detail"] = n.Detail
		}
		// withheld_advisories names the specific advisory ids this limit suppressed a verdict
		// for, when the producer identified them (e.g. a Go-toolchain advisory withheld under
		// ADR 0014 §3.3). Empty for a limit that narrows coverage without suppressing any
		// specific verdict (report.go's PartialityNote.Advisories doc). Enrichment on the
		// existing per-note result, not a separate result per id: a second id-keyed result set
		// would either lack the loud/quiet arm this result already carries, or duplicate it.
		if len(n.Advisories) > 0 {
			props["withheld_advisories"] = n.Advisories
		}
		out = append(out, SARIFResult{
			RuleID:  ruleID,
			Level:   level,
			Kind:    kind,
			Message: SARIFMessage{Text: reportSARIFPartialityText(n)},
			Locations: []SARIFLocation{{
				PhysicalLocation: &SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: sarifFallbackURI},
					Region:           &SARIFRegion{StartLine: 1},
				},
			}},
			Properties: &SARIFProperties{Tegron: props},
		})
	}
	return out
}

// reportSARIFPartialityText phrases one coverage limit for a code-scanning reader. It
// states what was not established and what that means for the results in this log; an
// unrecognized reason code is reported verbatim rather than dropped, since dropping it
// restores the silent clean-looking scan the disclosure exists to prevent.
//
// The two arms get different prose, not just different levels: a reader who sees only
// the message text must still be able to tell "this run skipped a step" from "this is
// how the method works everywhere".
func reportSARIFPartialityText(n report.PartialityNote) string {
	scope := "dependency"
	if n.Ecosystem != "" {
		scope = n.Ecosystem + " dependency"
	}
	suffix := ""
	if n.Detail != "" {
		suffix = fmt.Sprintf(" (%s)", n.Detail)
	}
	if n.EffectiveClass() == report.PartialityInherentLimit {
		return fmt.Sprintf(
			"Analysis limit: %s%s is an inherent limit of static analysis and holds for every "+
				"run of the %s analysis. It is reported for completeness — no step of this run "+
				"was skipped and no result in this log depends on it.",
			n.Reason, suffix, scope)
	}
	return fmt.Sprintf(
		"Partial coverage: part of the %s analysis could not be completed — %s%s. "+
			"The results in this run cover less than the whole codebase; advisories in the "+
			"unanalyzed part were not ruled out, they were not assessed.",
		scope, n.Reason, suffix)
}

// sarifFallbackURI is the location URI used when a finding's ecosystem maps to no
// known manifest (or the finding carries no package). GitHub code scanning rejects a
// result with no location ("expected at least one location"), so the projection MUST
// always emit a non-empty URI. "." denotes the repository root — a file-ish URI code
// scanning accepts — and keeps ingestion working for any future or unknown ecosystem.
const sarifFallbackURI = "."

// reportSARIFLocations returns exactly one location per finding, anchored to the
// dependency manifest for the package's ecosystem (the same mapping the Tier-0
// annotation surface uses). The Report carries no per-finding source line, so the
// manifest is the honest, deterministic anchor; startLine 1 means "somewhere in the
// manifest". The slice is never empty — an unknown ecosystem falls back to
// sarifFallbackURI so code-scanning ingestion can never break on a missing location.
func reportSARIFLocations(f report.AdvisoryFinding) []SARIFLocation {
	eco := ""
	if f.Package != nil {
		eco = f.Package.Ecosystem
	}
	uri := report.ManifestForEcosystem(eco)
	if uri == "" {
		uri = sarifFallbackURI
	}
	return []SARIFLocation{{
		PhysicalLocation: &SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{URI: uri},
			Region:           &SARIFRegion{StartLine: 1},
		},
	}}
}

// MarshalReportSARIF projects and JSON-encodes (indented) in one call.
func MarshalReportSARIF(r report.Report) ([]byte, error) {
	log, err := ProjectReportSARIF(r)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(log, "", "  ")
}

// reportSARIFLevelKind maps a deterministic verdict to a SARIF level + kind.
func reportSARIFLevelKind(v report.Verdict) (level, kind string) {
	switch v {
	case report.VerdictMaliciousPresent:
		// Decisive, not a candidate: a known-malicious package is present at a listed affected
		// version. "error" + "open" is the honest SARIF cell for a determined finding that owes
		// remediation — the one verdict for which "error" is truthful (see the level-mapping note).
		return "error", "open"
	case report.VerdictReachableCandidate:
		// A candidate owes follow-up (Prove tier). "warning" + "open" signals an
		// unresolved item — never "error" (which implies a proven finding).
		return "warning", "open"
	case report.VerdictNotExploitable:
		return "note", "informational"
	case report.VerdictDisqualified:
		return "none", "notApplicable"
	case report.VerdictUndetermined:
		// SARIF's own "requires human review", never an alert and never counted as a
		// finding. Deliberately NOT "notApplicable" (which would read as ruled out) and not
		// "informational" (which would read as settled).
		return "none", "review"
	default:
		return "warning", "open"
	}
}

// reportSARIFMessage builds an honest, human-readable result message.
func reportSARIFMessage(f report.AdvisoryFinding) string {
	switch f.Verdict {
	case report.VerdictMaliciousPresent:
		if f.Evidence.Detail != "" {
			return fmt.Sprintf("%s: known-malicious package present. %s. Remove or replace this dependency.", f.Advisory.ID, f.Evidence.Detail)
		}
		return fmt.Sprintf("%s: a known-malicious package is present at a version this advisory lists as affected. Remove or replace this dependency.", f.Advisory.ID)
	case report.VerdictReachableCandidate:
		if f.Evidence.ReachablePath != "" {
			return fmt.Sprintf(
				"%s: %s found a reachable candidate path (%s). This is a candidate for "+
					"exploitability, not a proof: proving it requires observing the path execute.",
				f.Advisory.ID, brand.Name, f.Evidence.ReachablePath)
		}
		return fmt.Sprintf(
			"%s: %s found a reachable candidate path. This is a candidate for "+
				"exploitability, not a proof: proving it requires observing the path execute.",
			f.Advisory.ID, brand.Name)
	case report.VerdictNotExploitable:
		if f.Evidence.Detail != "" {
			return fmt.Sprintf("%s: not exploitable. %s", f.Advisory.ID, f.Evidence.Detail)
		}
		return fmt.Sprintf("%s: not exploitable (grounded refutation).", f.Advisory.ID)
	case report.VerdictDisqualified:
		if f.Evidence.Detail != "" {
			return fmt.Sprintf("%s: disqualified. %s", f.Advisory.ID, f.Evidence.Detail)
		}
		return fmt.Sprintf("%s: disqualified (resolved version provably outside the affected range).", f.Advisory.ID)
	case report.VerdictUndetermined:
		// The closing sentence is the load-bearing one and is stated for every reason code: a
		// reader who takes "no verdict" for "no problem" has made exactly the inference the
		// original defect made on their behalf.
		return fmt.Sprintf(
			"%s: NOT ASSESSED. %s established no verdict for this advisory — %s. "+
				"This is not a statement that the codebase is unaffected.",
			f.Advisory.ID, brand.Name, report.UndeterminedDetail(f.UndeterminedReason))
	default:
		return f.Advisory.ID
	}
}
