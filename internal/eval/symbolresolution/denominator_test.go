package symbolresolution

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// goDenominators builds the {go} lane's D1–D4 over the real corpus with the given runner.
func goDenominators(t *testing.T, run CaseRunner, store pipeline.AttributionStore) []DenominatorReport {
	t.Helper()
	fixtures := loadCorpus(t)
	bound := bindFixtures(fixtures)
	outcomes := ClassifyLane(context.Background(), "go", pipeline.AdvisoryTable, bound, run)
	ctxs := buildRecordCtxs(pipeline.AdvisoryTable, store, bound, outcomes)
	return buildDenominators("go", len(pipeline.AdvisoryTable), ctxs)
}

// TestDenominatorsSideBySide is C3: every candidate denominator is computed side by side, each
// naming its definition, its included (denominator) count, and a rate that ALWAYS travels with
// its denominator (reachcandidate.Rate renders num/denom or "n/a (0/0)", never a bare float).
func TestDenominatorsSideBySide(t *testing.T) {
	reps := goDenominators(t, spreadRunner(loadCorpus(t)).run, pipeline.AttributionStore{})

	wantNames := []string{"ecosystem-in-lane", "symbol-bearing-in-lane", "reviewed-attributed-in-lane", "buildable-in-lane"}
	if len(reps) != len(wantNames) {
		t.Fatalf("got %d denominators, want %d", len(reps), len(wantNames))
	}
	// Known corpus shape (verified this session): 16 golang / 16 symbol-bearing / 0 reviewed / 7
	// buildable, over 38 total.
	wantIncluded := map[string]int{
		"ecosystem-in-lane":           16,
		"symbol-bearing-in-lane":      16,
		"reviewed-attributed-in-lane": 0,
		"buildable-in-lane":           7,
	}
	for i, rep := range reps {
		if rep.Name != wantNames[i] {
			t.Errorf("denominator %d name = %q, want %q", i, rep.Name, wantNames[i])
		}
		if rep.Lane != "go" {
			t.Errorf("denominator %q lane = %q, want go", rep.Name, rep.Lane)
		}
		if rep.Total != 38 {
			t.Errorf("denominator %q total = %d, want 38", rep.Name, rep.Total)
		}
		if rep.Included != wantIncluded[rep.Name] {
			t.Errorf("denominator %q included = %d, want %d", rep.Name, rep.Included, wantIncluded[rep.Name])
		}
		if rep.Rate.Denom != rep.Included {
			t.Errorf("denominator %q rate.denom = %d, want included %d", rep.Name, rep.Rate.Denom, rep.Included)
		}
		// A rate is never a bare float: its String carries "num/denom" or the n/a form.
		s := rep.Rate.String()
		if !strings.Contains(s, "/") {
			t.Errorf("denominator %q rate %q lacks its denominator", rep.Name, s)
		}
		// The empty (0-included) denominator renders honestly as n/a, never 0.0.
		if rep.Included == 0 && rep.Rate.String() != "n/a (0/0)" {
			t.Errorf("empty denominator %q renders %q, want n/a (0/0)", rep.Name, rep.Rate.String())
		}
	}
}

// TestDenominatorNumeratorFollowsResolution checks the uniform numerator: resolved==true within
// the included set. With spreadRunner, 3 of the 7 buildable records resolve, so D4's numerator is
// 3 and D1/D2 (same resolvable subset) also count 3.
func TestDenominatorNumeratorFollowsResolution(t *testing.T) {
	reps := goDenominators(t, spreadRunner(loadCorpus(t)).run, pipeline.AttributionStore{})
	byName := map[string]DenominatorReport{}
	for _, r := range reps {
		byName[r.Name] = r
	}
	if got := byName["buildable-in-lane"].Rate.Num; got != 3 {
		t.Errorf("buildable numerator = %d, want 3 (spreadRunner resolves 3 of 7)", got)
	}
	if got := byName["ecosystem-in-lane"].Rate.Num; got != 3 {
		t.Errorf("ecosystem numerator = %d, want 3 (only buildable records can resolve)", got)
	}
	if got := byName["symbol-bearing-in-lane"].Rate.Num; got != 3 {
		t.Errorf("symbol-bearing numerator = %d, want 3", got)
	}
}

// TestExclusionAccountingHolds is C4: for every denominator, included + Σ excluded == total, with
// every excluded record named in a bucket.
func TestExclusionAccountingHolds(t *testing.T) {
	reps := goDenominators(t, spreadRunner(loadCorpus(t)).run, pipeline.AttributionStore{})
	for _, rep := range reps {
		if err := rep.CheckAccounting(); err != nil {
			t.Errorf("denominator %q: %v", rep.Name, err)
		}
		// Every excluded record is nameable (records list length matches count).
		for _, b := range rep.Excluded {
			if len(b.Records) != b.Count {
				t.Errorf("denominator %q bucket %q: count %d but %d records listed", rep.Name, b.Reason, b.Count, len(b.Records))
			}
		}
	}
}

// TestExclusionMutationControlBites is the C4 mutation control: drop a record from a denominator
// WITHOUT recording its ExclusionBucket and the identity goes RED. The un-mutated report is green;
// the mutated copy (one record silently vanished) is red — proving the check bites.
func TestExclusionMutationControlBites(t *testing.T) {
	reps := goDenominators(t, spreadRunner(loadCorpus(t)).run, pipeline.AttributionStore{})
	// D1 has a populated exclusion bucket (22 out-of-lane records).
	var d1 DenominatorReport
	for _, r := range reps {
		if r.Name == "ecosystem-in-lane" {
			d1 = r
		}
	}
	if err := d1.CheckAccounting(); err != nil {
		t.Fatalf("baseline D1 must be green: %v", err)
	}
	if len(d1.Excluded) == 0 || len(d1.Excluded[0].Records) == 0 {
		t.Fatal("D1 has no excluded records to mutate — control is vacuous")
	}

	// Mutation: a record silently drops out of a bucket (Count decremented, record removed) and is
	// recorded NOWHERE else. Copy the buckets so we do not mutate the shared slice.
	mutated := d1
	mutated.Excluded = append([]ExclusionBucket(nil), d1.Excluded...)
	b0 := mutated.Excluded[0]
	b0.Records = b0.Records[:len(b0.Records)-1]
	b0.Count--
	mutated.Excluded[0] = b0

	if err := mutated.CheckAccounting(); err == nil {
		t.Fatal("dropping a record without recording its exclusion did NOT go red — the C4 identity does not bite")
	}
}

// TestD3AttributionStateExclusions checks the D3 attribution-state pathway (§4.1): with a synthetic
// store marking one golang record reviewed-attributed, D3 includes exactly that record, and every
// other in-lane symbol-bearing record is excluded under its NAMED reportState. The C4 identity
// still holds with a reportState string in the ExclusionBucket reason.
func TestD3AttributionStateExclusions(t *testing.T) {
	fixtures := loadCorpus(t)
	// Pick a real golang symbol-bearing record to mark reviewed-attributed.
	var target string
	for _, id := range boundGoBearingIDs(fixtures) {
		target = id
		break
	}
	if target == "" {
		t.Fatal("no golang bound record to attribute")
	}
	store := pipeline.AttributionStore{
		target: {Status: pipeline.AttributionConfirmed, Reviewer: "test", ReviewedAt: "2026-08-12T00:00:00Z", Citation: "upstream-fix"},
	}
	reps := goDenominators(t, spreadRunner(fixtures).run, store)
	var d3 DenominatorReport
	for _, r := range reps {
		if r.Name == "reviewed-attributed-in-lane" {
			d3 = r
		}
	}
	if d3.Included != 1 {
		t.Errorf("D3 included = %d, want 1 (only %s reviewed-attributed)", d3.Included, target)
	}
	if err := d3.CheckAccounting(); err != nil {
		t.Errorf("D3 accounting with attribution-state exclusions: %v", err)
	}
	// The unreviewed in-lane records are named under the "unreviewed" reportState bucket.
	var sawUnreviewed bool
	for _, b := range d3.Excluded {
		if string(b.Reason) == "unreviewed" {
			sawUnreviewed = true
		}
	}
	if !sawUnreviewed {
		t.Error("D3 excluded no records under the 'unreviewed' reportState — the attribution-state pathway is not exercised")
	}
}
