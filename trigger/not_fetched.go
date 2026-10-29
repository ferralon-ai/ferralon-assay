package trigger

import (
	"slices"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// The reassess list in depfetch.json names advisories a cve-watch run assessed while reading less
// dependency code than the lock pins. It is read here, from the record a store returned beside the
// stored report.json: a record written beside a different report.json reads as nil, so its list is
// never applied to rows it did not describe.
//
// The list is not an inventory of the verdicts reached without dependency code. A baseline that
// fell back adds nothing to it, and nothing in the stored report marks the verdicts such a baseline
// reached; a lost record drops it entirely. So the absence of an advisory from the list never means
// the advisory was assessed with its dependency code. Both uses below only ever withhold: they
// demote a listed advisory's refuting verdict, and they send a listed advisory back to assessment.
// Neither treats an unlisted advisory as anything.

// listedNotFetched reports whether f's advisory is on reassess, by its ID or one of its aliases.
func listedNotFetched(f report.AdvisoryFinding, reassess []string) bool {
	return slices.Contains(reassess, f.Advisory.ID) ||
		slices.ContainsFunc(f.Advisory.Aliases, func(a string) bool { return slices.Contains(reassess, a) })
}

// withNotFetched is rep with every advisory on dep's reassess list that holds a refuting verdict
// (disqualified or not_exploitable) withheld as undetermined dependency_not_fetched, and its
// dependency_not_fetched notes recomputed from the rows that carry the reason, so a row is never
// shown without its note or a note without its row. A reachable candidate, a malicious package and
// an existing undetermined row keep what they have: none of them claims the advisory does not
// apply. rep is not modified.
func withNotFetched(rep *report.Report, dep *statestore.DepFetch) (*report.Report, error) {
	var reassess []string
	if dep != nil {
		reassess = dep.Reassess
	}
	out := *rep
	rows := slices.Clone(rep.Advisories)
	var notes []report.PartialityNote
	for i, f := range rows {
		if (f.Verdict == report.VerdictDisqualified || f.Verdict == report.VerdictNotExploitable) && listedNotFetched(f, reassess) {
			f.Verdict = report.VerdictUndetermined
			f.UndeterminedReason = report.ReasonDependencyNotFetched
			f.Evidence = report.EvidenceSummary{Detail: report.UndeterminedDetail(report.ReasonDependencyNotFetched)}
			rows[i] = f
		}
		if f.UndeterminedReason != report.ReasonDependencyNotFetched {
			continue
		}
		if note, ok := limitNoteFor(f); ok {
			notes = append(notes, note)
		}
	}
	out.SetAdvisories(rows)
	out.Partiality = slices.DeleteFunc(slices.Clone(rep.Partiality), func(n report.PartialityNote) bool {
		return n.Reason == report.ReasonDependencyNotFetched
	})
	out.AddPartiality(notes...)
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

// notFetchedRetry is the stored rows a cve-watch run assesses again although their advisories are
// not new: every row on dep's reassess list, by ID or alias, and every row withheld as
// dependency_not_fetched, whatever source assessed it. The stored row is read as well as the list
// because the row survives a record that was lost or bound to another report. Each row is assessed
// again as itself, under its own source and package, so the fresh finding replaces exactly it; a
// row the run assesses anyway (a new advisory from OSV) is left to that assessment.
func notFetchedRetry(prior *report.Report, dep *statestore.DepFetch, newIDs []string) []report.AdvisoryFinding {
	var reassess []string
	if dep != nil {
		reassess = dep.Reassess
	}
	var out []report.AdvisoryFinding
	seen := map[string]bool{}
	for _, f := range prior.Advisories {
		if f.UndeterminedReason != report.ReasonDependencyNotFetched && !listedNotFetched(f, reassess) {
			continue
		}
		key := f.Advisory.ID + "\x00" + f.Advisory.Source
		if seen[key] || (f.Advisory.Source == osvSource && slices.Contains(newIDs, f.Advisory.ID)) {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// retriedIDs is the advisory IDs of rows, sorted, each once.
func retriedIDs(rows []report.AdvisoryFinding) []string {
	var out []string
	for _, f := range rows {
		out = append(out, f.Advisory.ID)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
