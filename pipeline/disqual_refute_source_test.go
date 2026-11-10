// disqual_refute_source_test.go
//
// A refute may be driven by any configured advisory source (tracker#633): a record's declared
// TrustTier never decides whether a version or symbol refute fires. Only an absent range blocks the
// version axis. Every refute names the record it relied on in DisqualResult.Source.
package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/internal/advisorytest"
)

// A provably out-of-range fact and a provably absent symbol each refute whatever tier the record
// declares, and the result names the record.
func TestRun_RefuteFromAnySource(t *testing.T) {
	tiers := []string{"first_party", "byo", "third_party", "", "vendor_hunch"}
	axes := []struct {
		name       string
		adv        map[string]any
		inv        map[string]any
		wantReason string
	}{
		{
			name:       "version outside range",
			adv:        map[string]any{"affected_ranges": []map[string]string{{"upper_exclusive": "v0.3.7"}}},
			inv:        map[string]any{"resolved_version": "v0.3.7", "resolved_versions": []string{"v0.3.7"}, "versions_complete": true},
			wantReason: ReasonVersionNotInRange,
		},
		{
			name:       "symbol absent",
			adv:        map[string]any{"vulnerable_symbol_presence": "absent"},
			inv:        map[string]any{},
			wantReason: ReasonSymbolAbsent,
		},
	}
	for _, ax := range axes {
		for _, tier := range tiers {
			t.Run(ax.name+"/tier="+tier, func(t *testing.T) {
				store := artifact.NewMemStore()
				caseID := "case-any-source"
				adv := map[string]any{
					"vuln_id":       "GO-2021-0113",
					"feed":          "customer-feed",
					"corpus":        "sha256:aaaa",
					"record_digest": "sha256:bbbb",
				}
				for k, v := range ax.adv {
					adv[k] = v
				}
				if tier != "" {
					adv["trust_tier"] = tier
				}
				putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, adv)
				putJSON(t, store, caseID, artifact.TypeInventory, ax.inv)

				res := runDisqual(t, store, caseID)
				if !res.Disqualified || res.Reason != ax.wantReason {
					t.Fatalf("got (%v, %q), want (true, %q)", res.Disqualified, res.Reason, ax.wantReason)
				}
				want := RefuteSource{Advisory: "GO-2021-0113", Corpus: "sha256:aaaa", Record: "sha256:bbbb", Feed: "customer-feed", TrustTier: tier}
				if res.Source == nil || *res.Source != want {
					t.Fatalf("Source = %+v, want %+v", res.Source, want)
				}
			})
		}
	}
}

// Without a range the version axis has nothing to compare against: the stage fails open and names
// no source, whatever the tier. An in-range version fails open the same way.
func TestRun_NoRefuteWithoutGrounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		adv  map[string]any
	}{
		{"no range at all", map[string]any{}},
		{"empty range list", map[string]any{"affected_ranges": []map[string]string{}}},
		{"version inside range", map[string]any{"affected_ranges": []map[string]string{{"upper_exclusive": "v0.3.8"}}}},
		{"symbol present", map[string]any{"vulnerable_symbol_presence": "present"}},
	} {
		for _, tier := range []string{"first_party", "byo", ""} {
			t.Run(tc.name+"/tier="+tier, func(t *testing.T) {
				store := artifact.NewMemStore()
				caseID := "case-no-grounds"
				adv := map[string]any{"vuln_id": "GO-2021-0113", "corpus": "sha256:aaaa"}
				for k, v := range tc.adv {
					adv[k] = v
				}
				if tier != "" {
					adv["trust_tier"] = tier
				}
				putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, adv)
				putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{"resolved_version": "v0.3.7", "resolved_versions": []string{"v0.3.7"}, "versions_complete": true})

				res := runDisqual(t, store, caseID)
				if res.Disqualified || res.Reason != ReasonInsufficient || res.Source != nil {
					t.Fatalf("got (%v, %q, %+v), want (false, %q, nil)", res.Disqualified, res.Reason, res.Source, ReasonInsufficient)
				}
			})
		}
	}
}

// End to end through a production-shaped bundle (records without a provenance block): an
// out-of-range version refutes and names the bundle's corpus digest and the record's digest pin,
// an in-range version and a range-less record do not refute.
func TestRun_BundleRefuteNamesRecord(t *testing.T) {
	const id = "CVE-TEST-REFUTE-SOURCE"
	record := func(t *testing.T, ranges []map[string]string) []byte {
		raw, err := os.ReadFile(filepath.Join(advisoryFixtureRoot, "FERRALON-TEST-0001.json"))
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal fixture: %v", err)
		}
		delete(m, "provenance")
		m["vuln_id"], m["module"], m["version_scheme"], m["purl"] = id, "example.com/a", "gomod", "pkg:golang/example.com/a"
		m["symbols"] = []string{"example.com/a.Sink"}
		m["fixed_version"] = "v1.2.0"
		m["affected_ranges"] = ranges
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return out
	}
	withRange := []map[string]string{{"introduced": "0", "fixed": "v1.2.0", "fixed_version": "v1.2.0"}}
	for _, tc := range []struct {
		name     string
		ranges   []map[string]string
		version  string
		wantDisq bool
	}{
		{"out of range refutes", withRange, "v1.3.0", true},
		{"in range stays", withRange, "v1.0.0", false},
		{"no range blocks", nil, "v1.3.0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := record(t, tc.ranges)
			path := writeBundle(t, []bundleEntry{entryFor(id, rec)})
			src := NewBundleSource(path)
			info, ok := src.(CorpusDescriber).Describe()
			if !ok {
				t.Fatalf("bundle unusable")
			}
			res := runRealDisqual(t, id, "go", src, map[string]string{
				"go.mod": "module example.com/target\n\ngo 1.21\n\nrequire example.com/a " + tc.version + "\n",
			})
			if res.Disqualified != tc.wantDisq {
				t.Fatalf("Disqualified = %v (%s), want %v", res.Disqualified, res.Reason, tc.wantDisq)
			}
			if !tc.wantDisq {
				if res.Source != nil {
					t.Fatalf("Source = %+v on a non-refute, want nil", res.Source)
				}
				return
			}
			want := RefuteSource{Advisory: id, Corpus: info.Digest, Record: advisorytest.Digest(rec)}
			if res.Source == nil || *res.Source != want {
				t.Fatalf("Source = %+v, want %+v", res.Source, want)
			}
		})
	}
}
