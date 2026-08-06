// report_vex.go
//
// OpenVEX projection driven by the neutral scan report.Report — the HEADLINE
// projection of the ferralon-assay OSS tool.
//
// This is the only VEX projector this module ships. The Service-tier projector
// over a single verdict.PoE lives service-side; it shares the OpenVEX document
// shapes declared in vex.go but not this file. The OSS tool never produces a
// PoE: it produces a Report carrying only the four deterministic verdicts
// invariant 5 permits the runner to emit. This projector maps FROM
// report.Verdict, never from verdict.PoE.
//
// Mapping (RFC 0001 inv. 5 — verdict honesty):
//
//	report.VerdictDisqualified       → OpenVEX "not_affected"        (justification: vulnerable_code_not_present
//	                                                                   when a version/symbol axis adjudicated the
//	                                                                   subject; none when Evidence.Basis is empty,
//	                                                                   i.e. no axis was adjudicated at all)
//	report.VerdictNotExploitable     → OpenVEX "not_affected"        (justification: vulnerable_code_not_present
//	                                                                   or _not_reachable, by Evidence.Basis)
//	report.VerdictReachableCandidate → OpenVEX "under_investigation" (NEVER "affected")
//	report.VerdictUndetermined       → OpenVEX "under_investigation" (no justification)
//
// "affected" is reserved for a PROVEN exploitable verdict, which the OSS tool
// cannot produce. A reachable candidate is exactly that — a candidate — and the
// only honest OpenVEX status for it is "under_investigation".
//
// An undetermined finding lands on the same status from the opposite direction: a
// candidate is "we found a path and cannot prove it fires", an undetermined finding
// is "we established nothing at all". OpenVEX has one cell for both, and it is the
// right one — "under_investigation" is the only status that asserts nothing.
package projection

import (
	"encoding/json"
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// ProjectReportVEX converts a report.Report into an OpenVEX document with one
// statement per advisory finding.
//
// The document timestamp and per-statement coordinates are derived from the
// Report's provenance and subject; no wall-clock is read, so the projection is
// deterministic and reproducible from the Report alone.
//
// The mapping is READ-ONLY and honest: a reachable_candidate is "under_investigation",
// never "affected" (inv. 5). The author is "ferralon-assay".
func ProjectReportVEX(r report.Report) (*VEXDocument, error) {
	if r.SchemaVersion == "" {
		return nil, fmt.Errorf("projection/report_vex: report has no schema version")
	}

	ts := r.Provenance.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00")

	stmts := make([]VEXStatement, 0, len(r.Advisories))
	for i := range r.Advisories {
		f := r.Advisories[i]
		status, just, impact := reportVEXStatus(f)

		stmt := VEXStatement{
			Vulnerability: VEXVulnerability{
				ID:      f.Advisory.ID,
				Aliases: f.Advisory.Aliases,
			},
			Products: []VEXProduct{{ID: reportProductID(f.Package, r.Subject)}},
			Status:   status,
		}
		if just != "" {
			stmt.Justification = just
		}
		if impact != "" {
			stmt.ImpactStatement = impact
		}
		stmts = append(stmts, stmt)
	}

	doc := &VEXDocument{
		Context:    OpenVEXSchemaVersion,
		ID:         fmt.Sprintf("https://openvex.dev/docs/%s/%s", brand.Name, reportDocSlug(r)),
		Author:     brand.Name,
		Timestamp:  ts,
		Version:    1,
		Statements: stmts,
	}
	return doc, nil
}

// MarshalReportVEX projects and JSON-encodes (indented) in one call.
func MarshalReportVEX(r report.Report) ([]byte, error) {
	doc, err := ProjectReportVEX(r)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(doc, "", "  ")
}

// reportVEXStatus maps one deterministic finding to an OpenVEX status,
// justification, and (for candidates) an impact statement.
func reportVEXStatus(f report.AdvisoryFinding) (status, justification, impact string) {
	switch f.Verdict {
	case report.VerdictDisqualified:
		// A disqualification is not_affected under every axis; the status is verdict-driven
		// (inv. 5) and does not vary. The JUSTIFICATION follows the Evidence basis, because
		// only some axes have one. A version or symbol disqualification adjudicated the
		// subject and cleared it — the vulnerable code is not present in any reachable form.
		// A disqualification carrying no basis was never adjudicated on either axis (the
		// advisory belongs to another ecosystem, or its package is absent from the manifest):
		// there are no grounds for vulnerable_code_not_present, which is a strictly stronger
		// claim than "not adjudicable here". OpenVEX §3.2 permits not_affected with no
		// justification, and that is the honest cell.
		switch f.Evidence.Basis {
		case verdict.BasisSymbolAbsent, verdict.BasisVersionNotAffected:
			return VEXStatusNotAffected, VEXJustNotPresent, ""
		default:
			return VEXStatusNotAffected, "", ""
		}

	case report.VerdictNotExploitable:
		// Grounded refutation. The OpenVEX justification follows the Evidence basis.
		switch f.Evidence.Basis {
		case verdict.BasisSymbolAbsent:
			return VEXStatusNotAffected, VEXJustNotPresent, ""
		case verdict.BasisVersionNotAffected:
			return VEXStatusNotAffected, VEXJustNotPresent, ""
		default:
			// No structured symbol/version basis recorded → the grounded refutation
			// is reachability-based.
			return VEXStatusNotAffected, VEXJustNotReachable, ""
		}

	case report.VerdictReachableCandidate:
		// A reachable path was found. This is a CANDIDATE, not a proof — the only
		// honest OpenVEX status is under_investigation. NEVER "affected" (inv. 5).
		msg := brand.Name + " found a reachable code path to the advisory symbol. " +
			"This is a candidate for exploitability, not a proof: proving it requires observing the path execute."
		if f.Evidence.ReachablePath != "" {
			msg = fmt.Sprintf("%s Candidate path: %s.", msg, f.Evidence.ReachablePath)
		}
		return VEXStatusUnderInvestigation, "", msg

	case report.VerdictUndetermined:
		// No verdict was established, so there is nothing to justify and nothing to
		// characterize as impact. The status alone is the whole honest statement; a
		// justification here would be the not_affected attestation ADR 0014 removed,
		// re-entering through the field that licenses it.
		//
		// This arm is stated explicitly even though the default arm below already returns
		// the same status: relying on the fallthrough would mean the correct mapping for a
		// first-class verdict was an accident of the default, and the next verdict added
		// would inherit it silently.
		return VEXStatusUnderInvestigation, "", ""

	default:
		// Unreachable: Report.Validate rejects any other verdict (inv. 5 structural guard).
		return VEXStatusUnderInvestigation, "", ""
	}
}

// reportProductID derives the OpenVEX product identifier for a finding. It prefers
// the package PURL, then falls back to ecosystem coordinates, then to the subject.
func reportProductID(pkg *report.Package, subj report.Subject) string {
	if pkg != nil {
		if pkg.PURL != "" {
			return pkg.PURL
		}
		if pkg.Name != "" {
			if pkg.Version != "" {
				return fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
			}
			return pkg.Name
		}
	}
	if subj.Repo != "" {
		if subj.ResolvedCommit != "" {
			return fmt.Sprintf("%s@%s", subj.Repo, subj.ResolvedCommit)
		}
		return subj.Repo
	}
	return brand.Name + "://subject/unknown"
}

// reportDocSlug builds a stable, URL-safe document-id suffix from the subject.
func reportDocSlug(r report.Report) string {
	if r.Subject.ResolvedCommit != "" {
		return r.Subject.ResolvedCommit
	}
	if r.Provenance.CommitSHA != "" {
		return r.Provenance.CommitSHA
	}
	return "report"
}
