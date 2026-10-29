package statestore

import (
	"encoding/json"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// Merge re-applies the local writer's intent (mine) onto the state a concurrent
// winner committed (base) after a CAS conflict. It is the convergence rule the
// retry loop uses so a race-loser does not clobber the winner's work.
//
// Rules (per the Phase-2 plan):
//
//   - Advisories: UNION across both Reports, keyed by (advisory id, source). When
//     both sides evaluated the same advisory, the verdict with the LATER provenance
//     timestamp wins (the more recent analysis is authoritative). Ties (equal
//     timestamps) keep mine, since mine is the write being retried.
//   - SBOM / Subject / Provenance: taken from whichever Report has the later
//     provenance timestamp (the more recent full scan describes the current tree).
//     The one exception is Provenance.Intel.SignalsDigest: the union can carry a row
//     the later Report's signals file never ranked, so when any merged row came from a
//     Report that recorded a different digest (or none) than the later Report did, the
//     digest is left empty rather than naming a file that did not rank that row. This
//     holds for unranked rows too: a row with no Priority under a named file reads as
//     "the file holds no usable signal for this advisory (no record, or a refused
//     join)", which only the file that ranked it can say.
//   - Cursor: the later Report's cursor (it advanced with the newer scan); if the
//     winner has no Report, mine's cursor is kept.
//   - VEXLog: append-union — base's log followed by any of mine's entries not
//     already present (dedup by exact bytes), preserving the winner's history and
//     adding mine's new statements.
//
// The returned State carries base.CommitSHA as its CAS token so the caller retries
// the CAS against the winner's commit.
func Merge(base, mine *State) *State {
	out := &State{CommitSHA: base.CommitSHA}

	out.Report = mergeReports(reportOf(base), reportOf(mine))
	if out.Report != nil {
		out.SBOM = out.Report.SBOM
		out.Cursor = out.Report.Provenance.AdvisoryCursor
	}
	// If neither side had a cursor in provenance, fall back to the raw cursor fields.
	if out.Cursor == "" {
		out.Cursor = laterCursor(base, mine)
	}
	out.VEXLog = mergeVEXLogs(base.VEXLog, mine.VEXLog)
	// Revoke counter: take the larger of the two so a CAS retry can never lose an
	// increment the winner recorded. A reset-to-0 racing an increment is pathological
	// (two runs observing contradictory ingest responses at once) and self-corrects on
	// the next run; never-losing-an-increment is the safety property that matters.
	out.RevokeCount = base.RevokeCount
	if mine.RevokeCount > out.RevokeCount {
		out.RevokeCount = mine.RevokeCount
	}
	return out
}

func reportOf(s *State) *report.Report {
	if s == nil {
		return nil
	}
	return s.Report
}

// mergeReports unions two Reports' advisories (latest-timestamp-per-advisory wins)
// and takes scalar fields from the later-timestamped Report. The result is rebuilt
// through report.Builder so its SBOM and findings are sorted into the canonical
// stable order — preserving the zero-new-objects guarantee on the next write.
func mergeReports(base, mine *report.Report) *report.Report {
	switch {
	case base == nil && mine == nil:
		return nil
	case base == nil:
		return mine
	case mine == nil:
		return base
	}

	// The "primary" is the later-timestamped Report: it supplies Subject, SBOM,
	// Provenance, and Baseline. The other only contributes advisories the primary
	// lacks (or newer per-advisory verdicts).
	primary, secondary := base, mine
	if mine.Provenance.Timestamp.After(base.Provenance.Timestamp) {
		primary, secondary = mine, base
	}

	type key struct{ id, source string }
	chosen := make(map[key]report.AdvisoryFinding)
	from := make(map[key]*report.Report)
	order := []key{}
	add := func(f report.AdvisoryFinding, src *report.Report, ts func(report.AdvisoryFinding) bool) {
		k := key{f.Advisory.ID, f.Advisory.Source}
		if prev, ok := chosen[k]; ok {
			if ts(prev) {
				chosen[k] = f
				from[k] = src
			}
			return
		}
		chosen[k] = f
		from[k] = src
		order = append(order, k)
	}
	// Seed with the secondary, then let the primary override on equal-or-later
	// timestamp. Per-advisory the winner is the finding from the Report with the
	// later provenance timestamp; on a tie the primary (later overall) wins, and
	// when timestamps are equal the retrying writer (mine) is the primary only if it
	// is strictly later — equal overall keeps base as primary, so base's findings win
	// ties, matching "the committed winner stands unless mine is newer".
	for _, f := range secondary.Advisories {
		add(f, secondary, func(report.AdvisoryFinding) bool { return false })
	}
	primaryNewer := primary.Provenance.Timestamp.After(secondary.Provenance.Timestamp) ||
		primary.Provenance.Timestamp.Equal(secondary.Provenance.Timestamp)
	for _, f := range primary.Advisories {
		add(f, primary, func(report.AdvisoryFinding) bool { return primaryNewer })
	}

	// A source-less `undetermined` row is what report.Upgrade produces from a stored v1
	// document's withheld-advisory list — a v1 partiality note named the id alone, so the
	// migrated row has no source to key on. When the other side evaluated the same advisory
	// under a real source, its keyed finding is the answer; keeping both would union one
	// advisory into two rows.
	sourced := make(map[string]struct{}, len(order))
	for _, k := range order {
		if k.source != "" {
			sourced[k.id] = struct{}{}
		}
	}
	kept := make([]key, 0, len(order))
	for _, k := range order {
		if k.source == "" && chosen[k].Verdict == report.VerdictUndetermined {
			if _, ok := sourced[k.id]; ok {
				continue
			}
		}
		kept = append(kept, k)
	}

	prov := primary.Provenance
	for _, k := range kept {
		if signalsDigestOf(from[k]) != signalsDigestOf(primary) {
			prov.Intel = withoutSignalsDigest(prov.Intel)
			break
		}
	}
	b := report.NewBuilder(primary.Subject).
		AddPackages(primary.SBOM.Packages...).
		WithProvenance(prov)
	if primary.Baseline != nil {
		b.WithBaseline(*primary.Baseline)
	}
	for _, k := range kept {
		b.AddFinding(chosen[k])
	}
	// Partiality is UNIONED, not taken from the primary: the merged advisory set is a
	// union too, so a limit that bound the secondary's findings still bounds them here.
	// Erring toward disclosing a limit that has since been resolved is the safe
	// direction; erring the other way silently re-cleans a partial scan.
	b.AddPartiality(primary.Partiality...)
	b.AddPartiality(secondary.Partiality...)
	merged := b.Build()
	return &merged
}

// signalsDigestOf is the signals file r records having ranked its rows with; empty when it records
// none.
func signalsDigestOf(r *report.Report) string {
	if r.Provenance.Intel == nil {
		return ""
	}
	return r.Provenance.Intel.SignalsDigest
}

// withoutSignalsDigest returns a copy of in with SignalsDigest cleared, leaving in untouched. When
// nothing else is left in the copy it returns nil: trigger.Run* writes a block holding the digest
// alone, and no digest means no Intel block, as it does on a run with no signals.
func withoutSignalsDigest(in *report.IntelProvenance) *report.IntelProvenance {
	if in == nil {
		return nil
	}
	out := *in
	out.SignalsDigest = ""
	if out == (report.IntelProvenance{}) {
		return nil
	}
	return &out
}

func laterCursor(base, mine *State) string {
	if mine.Cursor != "" {
		return mine.Cursor
	}
	return base.Cursor
}

// mergeVEXLogs append-unions two NDJSON logs: base's entries first, then mine's
// entries not already present (dedup by exact canonical bytes).
func mergeVEXLogs(base, mine []json.RawMessage) []json.RawMessage {
	seen := make(map[string]struct{}, len(base))
	out := make([]json.RawMessage, 0, len(base)+len(mine))
	for _, e := range base {
		c := canonicalJSON(e)
		if _, ok := seen[string(c)]; ok {
			continue
		}
		seen[string(c)] = struct{}{}
		out = append(out, e)
	}
	for _, e := range mine {
		c := canonicalJSON(e)
		if _, ok := seen[string(c)]; ok {
			continue
		}
		seen[string(c)] = struct{}{}
		out = append(out, e)
	}
	return out
}

// canonicalJSON returns a stable byte form of a JSON value for dedup comparison:
// it re-marshals through a generic decode so semantically-identical statements with
// different whitespace compare equal. On a parse failure it returns the raw bytes.
func canonicalJSON(raw json.RawMessage) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}
