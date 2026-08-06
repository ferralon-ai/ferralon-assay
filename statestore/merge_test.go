package statestore

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

func TestMergeTakesLargerRevokeCount(t *testing.T) {
	t0 := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	base := &State{Report: sampleReport("b", "cb", t0), CommitSHA: "sha-base", RevokeCount: 2}
	mine := &State{Report: sampleReport("m", "cm", t0.Add(time.Hour)), RevokeCount: 1}

	if out := Merge(base, mine); out.RevokeCount != 2 {
		t.Errorf("merge must keep the larger revoke count (never lose an increment): got %d want 2", out.RevokeCount)
	}
	// Symmetric: mine ahead of base.
	base.RevokeCount, mine.RevokeCount = 1, 3
	if out := Merge(base, mine); out.RevokeCount != 3 {
		t.Errorf("merge take-max wrong: got %d want 3", out.RevokeCount)
	}
}

func TestMergeUnionsAdvisories(t *testing.T) {
	t0 := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	base := &State{Report: sampleReport("b", "cb", t0, "GO-A", "GO-SHARED"), CommitSHA: "sha-base"}
	mine := &State{Report: sampleReport("m", "cm", t0.Add(time.Hour), "GO-B", "GO-SHARED")}

	out := Merge(base, mine)
	if out.CommitSHA != "sha-base" {
		t.Errorf("merge must retain base CommitSHA for retry, got %q", out.CommitSHA)
	}
	ids := map[string]bool{}
	for _, f := range out.Report.Advisories {
		ids[f.Advisory.ID] = true
	}
	for _, want := range []string{"GO-A", "GO-B", "GO-SHARED"} {
		if !ids[want] {
			t.Errorf("union missing %q (have %v)", want, ids)
		}
	}
	// GO-SHARED appears once (deduped by id+source).
	count := 0
	for _, f := range out.Report.Advisories {
		if f.Advisory.ID == "GO-SHARED" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("GO-SHARED appears %d times, want 1 (dedup)", count)
	}
}

// TestMergeLatestTimestampWins: when both sides evaluated the same advisory with
// different verdicts, the later-provenance-timestamp verdict wins.
func TestMergeLatestTimestampWins(t *testing.T) {
	t0 := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)

	older := report.NewBuilder(report.Subject{ResolvedCommit: "old"}).
		WithProvenance(report.Provenance{Timestamp: t0}).
		ReachableCandidate(report.Advisory{ID: "GO-X", Source: "osv"}, nil, "h->v", "").
		Build()
	newer := report.NewBuilder(report.Subject{ResolvedCommit: "new"}).
		WithProvenance(report.Provenance{Timestamp: t0.Add(time.Hour)}).
		Disqualified(report.Advisory{ID: "GO-X", Source: "osv"}, nil, verdict.BasisVersionNotAffected, "version below affected").
		Build()

	// base = older committed; mine = newer retrying. Newer must win.
	out := Merge(&State{Report: &older, CommitSHA: "x"}, &State{Report: &newer})
	if got := out.Report.Advisories[0].Verdict; got != report.VerdictDisqualified {
		t.Errorf("later verdict should win: got %q want disqualified", got)
	}

	// Reverse: base = newer committed; mine = older retrying. Newer (base) still wins.
	out2 := Merge(&State{Report: &newer, CommitSHA: "y"}, &State{Report: &older})
	if got := out2.Report.Advisories[0].Verdict; got != report.VerdictDisqualified {
		t.Errorf("later verdict should win regardless of base/mine role: got %q", got)
	}
}

func TestMergeVEXLogAppendUnion(t *testing.T) {
	a := json.RawMessage(`{"v":1}`)
	b := json.RawMessage(`{"v":2}`)
	bDup := json.RawMessage(`{ "v": 2 }`) // same value, different whitespace
	c := json.RawMessage(`{"v":3}`)

	base := &State{VEXLog: []json.RawMessage{a, b}, CommitSHA: "x"}
	mine := &State{VEXLog: []json.RawMessage{bDup, c}}

	out := Merge(base, mine)
	if len(out.VEXLog) != 3 {
		t.Fatalf("want 3 unique entries (a,b,c), got %d: %s", len(out.VEXLog), out.VEXLog)
	}
}

func TestMergeNilSides(t *testing.T) {
	t0 := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	mine := &State{Report: sampleReport("m", "cm", t0), CommitSHA: ""}
	out := Merge(&State{CommitSHA: "base"}, mine)
	if out.Report == nil {
		t.Fatal("merge with empty base should keep mine's report")
	}
	if out.CommitSHA != "base" {
		t.Errorf("CommitSHA should be base's, got %q", out.CommitSHA)
	}
}
