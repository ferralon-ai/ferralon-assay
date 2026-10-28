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

// signalsReport is sampleReport with each row ranked by a signals file named digest ("" records none).
func signalsReport(commit string, ts time.Time, digest string, ids ...string) *report.Report {
	r := sampleReport(commit, "c", ts, ids...)
	if digest != "" {
		r.Provenance.Intel = &report.IntelProvenance{WorkSetSource: report.WorkSetOSVQuery, SignalsDigest: digest}
	}
	for i := range r.Advisories {
		r.Advisories[i].Priority = &report.Priority{KEVCatalogVersion: "v", KEVDateReleased: "2026-10-19T00:00:00Z"}
	}
	return r
}

// TestMergeSignalsDigest: a merged Report names a signals file only when it ranked every
// row that carries a Priority. A row ranked by the other side's file, or by an unrecorded one, must
// not be published under the kept provenance's digest.
func TestMergeSignalsDigest(t *testing.T) {
	t0 := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	const a, b = "sha256:aaa", "sha256:bbb"
	for _, c := range []struct {
		name       string
		base, mine *report.Report
		want       string
	}{
		{"same file on both sides keeps it", signalsReport("b", t0, a, "GO-A"), signalsReport("m", t0.Add(time.Hour), a, "GO-B"), a},
		{"a row ranked by another file clears it", signalsReport("b", t0, a, "GO-A"), signalsReport("m", t0.Add(time.Hour), b, "GO-B"), ""},
		{"the later side's own rows keep its digest when the older side's rows are all shadowed", signalsReport("b", t0, a, "GO-A"), signalsReport("m", t0.Add(time.Hour), b, "GO-A"), b},
		{"rows from a binary that recorded no digest clear it", signalsReport("b", t0, "", "GO-A"), signalsReport("m", t0.Add(time.Hour), b, "GO-B"), ""},
		{"no priority rows from the other side keeps it", sampleReport("b", "c", t0, "GO-A"), signalsReport("m", t0.Add(time.Hour), b, "GO-B"), b},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := Merge(&State{Report: c.base, CommitSHA: "sha-base"}, &State{Report: c.mine}).Report
			got := ""
			if out.Provenance.Intel != nil {
				got = out.Provenance.Intel.SignalsDigest
			}
			if got != c.want {
				t.Errorf("merged SignalsDigest = %q, want %q", got, c.want)
			}
			// The inputs are never edited: a retry re-merges from the same Reports.
			for _, in := range []*report.Report{c.base, c.mine} {
				if in.Provenance.Intel != nil && in.Provenance.Intel.SignalsDigest == "" {
					t.Errorf("Merge cleared the digest on one of its inputs")
				}
			}
		})
	}
}
