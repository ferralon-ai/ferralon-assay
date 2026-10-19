package pipeline

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// TestAdvisoryRangeAbsent_Projection drives decoded ranges through buildAffectedRanges into the
// normalized artifact, so a bound the version axis drops still reaches the absent predicate.
func TestAdvisoryRangeAbsent_Projection(t *testing.T) {
	cases := []struct {
		name       string
		ranges     []Range
		upper      string
		wantAbsent bool
		wantBounds []RecordedBound
	}{
		{name: "no range at all", wantAbsent: true},
		{name: "fixed", ranges: []Range{{Introduced: "0", Fixed: "2.0.0"}}},
		{name: "introduced above zero with a fix", ranges: []Range{{Introduced: "1.0.0", Fixed: "2.0.0"}}},
		{name: "introduced zero only: every version", ranges: []Range{{Introduced: "0"}}},
		{name: "introduced 0.0.0 only: every version", ranges: []Range{{Introduced: "0.0.0"}}},
		{name: "scalar upper bound only", upper: "2.0.0"},
		{name: "last_affected only", ranges: []Range{{Introduced: "0", LastAffected: "1.4.0"}}},
		{name: "introduced above zero only", ranges: []Range{{Introduced: "2.0.0"}}},
		{name: "introduced and last_affected, two ranges", ranges: []Range{{Introduced: "1.0.0", LastAffected: "1.2.0"}, {Introduced: "2.0.0"}}},
		{name: "SEMVER and ECOSYSTEM ranges order", ranges: []Range{{Type: "SEMVER", Introduced: "2.0.0"}, {Type: "ECOSYSTEM", LastAffected: "1.4.0"}}},
		{
			name: "GIT ranges only",
			ranges: []Range{
				{Type: "GIT", Introduced: "9f3e2a1b", LastAffected: "c0ffee12"},
				{Type: "GIT", Fixed: "abc1234"},
				{Type: "GIT", Introduced: "0.0.0", LastAffected: "deadbeef"},
			},
			wantAbsent: true,
			wantBounds: []RecordedBound{{Introduced: "9f3e2a1b", LastAffected: "c0ffee12"}, {LastAffected: "deadbeef"}},
		},
		{name: "an unrecognized range type", ranges: []Range{{Type: "FOO", Introduced: "0", Fixed: "2.0.0"}}, wantAbsent: true},
		{name: "a GIT range beside an ordered one", ranges: []Range{{Type: "GIT", Introduced: "9f3e2a1b"}, {Introduced: "2.0.0"}}},
		{
			name:   "one bounded range among unbounded ones",
			ranges: []Range{{Introduced: "2.0.0"}, {Introduced: "0", Fixed: "1.5.0"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			putJSON(t, store, "c", artifact.TypeNormalizedAdvisory, map[string]any{
				"affected_ranges": buildAffectedRanges(tc.ranges, tc.upper, "pypi"),
			})
			if got := AdvisoryRangeAbsent(store, "c"); got != tc.wantAbsent {
				t.Errorf("AdvisoryRangeAbsent = %v, want %v", got, tc.wantAbsent)
			}
			if got := AdvisoryRecordedBounds(store, "c"); !reflect.DeepEqual(got, tc.wantBounds) {
				t.Errorf("AdvisoryRecordedBounds = %+v, want %+v", got, tc.wantBounds)
			}
		})
	}
}
