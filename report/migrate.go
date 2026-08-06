package report

import "fmt"

// Upgrade brings a decoded Report up to the current SchemaVersion, returning an error
// for any schema_version it does not recognize. It is the migration path required by
// the contract's §11 bump rules, and it is the ONLY place a stored document's version
// is interpreted.
//
// Readers upgrade on read: nothing in the tree rewrites stored state to migrate it, so
// a StateStore written before the bump is upgraded every time it is read, and the
// document on the ref is only replaced when a run writes state for its own reasons. A
// read-only consumer therefore never has to know v1 existed.
//
// Refusing an unrecognized version is deliberate and is what the contract requires of
// every reader: a document from a FUTURE schema may have changed the meaning of a field
// this code reads, and guessing at it is how a reader silently reports a verdict the
// producer did not emit.
func Upgrade(r Report) (Report, error) {
	switch r.SchemaVersion {
	case SchemaVersion:
		return r, nil
	case SchemaVersionV1:
		return upgradeV1(r), nil
	case "":
		return Report{}, fmt.Errorf("report: document carries no schema_version (uninterpretable)")
	default:
		return Report{}, fmt.Errorf("report: unrecognized schema_version %q (this reader understands %q and %q)",
			r.SchemaVersion, SchemaVersion, SchemaVersionV1)
	}
}

// upgradeV1 converts the v1 withholding shape into v2's first-class rows: each id in a
// partiality[].advisories list becomes one undetermined finding carrying that note's
// reason, and the note's list empties.
//
// The note itself survives with its reason and ecosystem. That is not residue — it is the
// only carrier of the limit's ECOSYSTEM scope (an undetermined row has no ecosystem field:
// its Package is nil, because the Go toolchain is not an SBOM dependency), and it is what a
// freshly-produced v2 report emits beside the same rows. Upgrading and re-producing the
// same scan therefore converge on one shape.
//
// An id that somehow appears BOTH as an existing row and in a withheld list is not
// duplicated: the row wins and the id is dropped from the list. v1's producer could not
// emit that combination, but this is a boundary over documents written by other versions,
// so it is checked rather than assumed.
func upgradeV1(r Report) Report {
	out := r
	out.SchemaVersion = SchemaVersion

	present := make(map[string]struct{}, len(r.Advisories))
	for i := range r.Advisories {
		present[r.Advisories[i].Advisory.ID] = struct{}{}
	}

	advisories := append([]AdvisoryFinding(nil), r.Advisories...)
	notes := make([]PartialityNote, 0, len(r.Partiality))
	for _, n := range r.Partiality {
		// A limit that named itself nothing still withheld real advisories, and Validate forbids
		// carrying an empty reason onto the rows. Substituting an explicit code is the only option
		// that keeps the advisory nameable without either failing validation downstream or
		// silently dropping it — see ReasonUnspecifiedLimit for why both alternatives are worse.
		reason := n.Reason
		if reason == "" {
			reason = ReasonUnspecifiedLimit
		}
		for _, id := range n.Advisories {
			if id == "" {
				continue
			}
			if _, ok := present[id]; ok {
				continue
			}
			present[id] = struct{}{}
			advisories = append(advisories, AdvisoryFinding{
				// Source is left empty: a v1 note carried the id alone, and inventing the
				// advisory database it came from would be a fabricated fact.
				Advisory:           Advisory{ID: id},
				Verdict:            VerdictUndetermined,
				UndeterminedReason: reason,
				Evidence:           EvidenceSummary{Detail: UndeterminedDetail(reason)},
			})
		}
		n.Advisories = nil
		notes = append(notes, n)
	}

	sortFindings(advisories)
	out.Advisories = advisories
	out.Partiality = notes
	return out
}

// UndeterminedDetail is the neutral one-line grounds-free explanation for an undetermined
// finding, keyed by reason code. It states what was not established and never implies the
// codebase is unaffected. An unrecognized code falls through to the raw code rather than to
// silence: the vocabulary is open, and a row whose reason renders as nothing is the silent
// suppression the verdict exists to end.
func UndeterminedDetail(reason string) string {
	switch reason {
	case ReasonGoToolchainUnresolved:
		return "the Go toolchain version this codebase builds with could not be determined, so no verdict was established for an advisory affecting the toolchain itself"
	case ReasonGoToolchainNotScanned:
		return "the analysis did not run under this codebase's own Go toolchain version, so no verdict was established for an advisory affecting the toolchain itself"
	case ReasonAnalysisDidNotRun:
		return "the analysis steps that would locate this advisory's code in what this repository builds did not run, so no verdict was established: finding no path is a fact about the analysis here, not about this codebase"
	case ReasonUnspecifiedLimit:
		return "no verdict was established for this advisory, and the stored report this row was migrated from did not record which limit prevented it"
	default:
		return "no verdict was established for this advisory (" + reason + ")"
	}
}
