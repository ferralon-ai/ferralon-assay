// advisory_kev_attribution_live_test.go
//
// The attribution guard (TestKEVAttributionFollowsListedCVE) measured against the corpus's REAL
// signals file rather than a fixture. It counts the AdvisoryTable entries whose signals come from
// a record that is not their own two ways: through #167's join (the first record any of the
// entry's id and aliases has) and through intel.Signals.Attribute. The invariant it enforces is the
// guard's: after the fix, no entry takes another advisory's record, and no CVE-keyed entry takes a
// record through an alias.
//
// Opt-in — set ASSAY_ATTRIBUTION_SIGNALS to a signals.json or signals.json.gz. It is skipped
// otherwise, so it never gates CI on an artifact the public module does not carry.
//
//	ASSAY_ATTRIBUTION_SIGNALS=/path/to/signals.json go test ./pipeline -run AttributionOverRealSignals -v
package pipeline

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/intel"
)

func TestKEVAttributionOverRealSignals(t *testing.T) {
	path := os.Getenv("ASSAY_ATTRIBUTION_SIGNALS")
	if path == "" {
		t.Skip("set ASSAY_ATTRIBUTION_SIGNALS to a signals file to run the live attribution measurement")
	}
	sig, err := intel.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("signals: %d records, digest %s", sig.Records(), sig.Digest)

	claims := tableClaims()
	// legacy is #167's join: per value, the first of id+aliases the file has one for.
	legacy := func(id string, aliases []string) (epssFrom, kevFrom string) {
		for _, x := range append([]string{id}, aliases...) {
			if e, ok := sig.EPSS(x); ok && epssFrom == "" {
				epssFrom = e.Identifier
			}
			if k, ok := sig.KEV(x); ok && kevFrom == "" {
				kevFrom = k.Identifier
			}
		}
		return epssFrom, kevFrom
	}
	ids := make([]string, 0, len(AdvisoryTable))
	for id := range AdvisoryTable {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var before, after int
	for _, id := range ids {
		facts := AdvisoryTable[id]
		epssFrom, kevFrom := legacy(id, facts.Aliases)
		if strings.HasPrefix(id, "CVE-") && ((epssFrom != "" && epssFrom != id) || (kevFrom != "" && kevFrom != id)) {
			before++
			t.Logf("before: %s takes EPSS from %q, KEV from %q", id, epssFrom, kevFrom)
		}
		m, ok := sig.Attribute(id, facts.Aliases, claims)
		if !ok || m.Identifier == id {
			continue
		}
		if strings.HasPrefix(id, "CVE-") || claims.ClaimedByOther(m.Identifier, id) {
			after++
			t.Errorf("after: %s takes its signals from %s", id, m.Identifier)
		} else {
			t.Logf("after: %s takes its signals from its CVE alias %s (no other entry names it)", id, m.Identifier)
		}
	}
	t.Logf("CVE-keyed entries taking a record not their own: before %d, after %d", before, after)
}
