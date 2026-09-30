// advisory_source_index_test.go
//
// artifactSource loads its manifest once and indexes it by identifier, and Refresh reloads it only
// when the manifest file changed. These tests pin that the manifest is read exactly once across many
// Lookup/Validate/Describe/Refresh calls while it is unchanged, that every outcome (hit, missing id,
// unreadable or invalid manifest) is stable, that a rewrite is picked up at the next Refresh (and at
// the next advisory_intake run), that a corrupt rewrite keeps the last good index and reports the
// error, and that all of it is race-free.
package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// countingSource returns an artifactSource over root whose manifest reads are counted.
func countingSource(root string, reads *atomic.Int64) *artifactSource {
	return &artifactSource{
		root: root,
		readFile: func(path string) ([]byte, error) {
			reads.Add(1)
			return os.ReadFile(path)
		},
	}
}

func TestArtifactSource_ManifestReadOnceAcrossLookups(t *testing.T) {
	const n = 50
	tests := []struct {
		name      string
		root      string
		vulnID    string
		wantOK    bool
		wantValid bool
	}{
		{"hit", advisoryFixtureRoot, "FERRALON-TEST-0001", true, true},
		{"missing id", advisoryFixtureRoot, "FERRALON-TEST-NOPE", false, true},
		{"digest mismatch", advisoryFixtureRoot, "FERRALON-TEST-BADDIGEST", false, true},
		{"manifest read error", "testdata/advisory_source/does-not-exist", "FERRALON-TEST-0001", false, false},
		{"record_count mismatch", "testdata/advisory_source/badcount", "FERRALON-TEST-BADCOUNT", false, false},
		{"duplicate identifier", "testdata/advisory_source/dupid", "FERRALON-TEST-DUP", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reads atomic.Int64
			src := countingSource(tt.root, &reads)

			if err := src.Validate(); (err == nil) != tt.wantValid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tt.wantValid)
			}
			for i := 0; i < n; i++ {
				_ = src.Refresh() // unchanged manifest: a stat, never a re-read
				_, ok := src.Lookup(tt.vulnID)
				if ok != tt.wantOK {
					t.Fatalf("Lookup(%s) #%d ok=%v, want %v", tt.vulnID, i, ok, tt.wantOK)
				}
			}
			if _, ok := src.Describe(); ok != tt.wantValid {
				t.Errorf("Describe() ok=%v, want %v", ok, tt.wantValid)
			}
			if err := src.Validate(); (err == nil) != tt.wantValid {
				t.Errorf("second Validate() = %v, want valid=%v (the load outcome must not change)", err, tt.wantValid)
			}
			if got := reads.Load(); got != 1 {
				t.Errorf("manifest read %d times across %d Refresh+Lookup pairs + Validate + Describe, want 1", got, n)
			}
		})
	}
}

// The index must resolve the same record the manifest names, so a load-once source returns facts
// identical to a fresh source's first Lookup.
func TestArtifactSource_IndexedLookupMatchesFreshSource(t *testing.T) {
	cached := NewArtifactSource(advisoryFixtureRoot)
	cached.Lookup("FERRALON-TEST-NOPE") // force the load through a miss first
	got, ok := cached.Lookup("FERRALON-TEST-0001")
	want, wantOK := NewArtifactSource(advisoryFixtureRoot).Lookup("FERRALON-TEST-0001")
	if ok != wantOK || !ok {
		t.Fatalf("ok=%v, fresh ok=%v, want both true", ok, wantOK)
	}
	if got.Coordinate != want.Coordinate || got.UpperExclusive != want.UpperExclusive || got.PURL != want.PURL {
		t.Errorf("cached Lookup = %+v, fresh Lookup = %+v", got, want)
	}
}

// Many goroutines hitting one fresh source race the lazy load; under -race this proves the load is
// safely published and the manifest is still read once.
func TestArtifactSource_ConcurrentLookupLoadsOnce(t *testing.T) {
	var reads atomic.Int64
	src := countingSource(advisoryFixtureRoot, &reads)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				if _, ok := src.Lookup("FERRALON-TEST-0001"); !ok {
					t.Error("concurrent Lookup(FERRALON-TEST-0001) ok=false, want true")
				}
			case 1:
				if err := src.Validate(); err != nil {
					t.Errorf("concurrent Validate() = %v, want nil", err)
				}
			default:
				if _, ok := src.Describe(); !ok {
					t.Error("concurrent Describe() ok=false, want true")
				}
			}
		}(i)
	}
	wg.Wait()
	if got := reads.Load(); got != 1 {
		t.Errorf("manifest read %d times under concurrent use, want 1", got)
	}
}

// Two manifests over the same fixture documents: v1 names only FERRALON-TEST-0001, v2 adds
// FERRALON-TEST-DATED. Lookup(FERRALON-TEST-DATED) therefore tells which manifest is being served.
const (
	manifestV1 = `{"manifest_version":"1.0.0","schema_version":"ferralon.normalized_advisory.v2","record_count":1,"records":[
{"identifier":"FERRALON-TEST-0001","path":"FERRALON-TEST-0001.json","output_digest":"sha256:05b1935b9969a04c01692e9242601c91888ff0b88ab7660ecad362f2c8242644"}]}`
	manifestV2 = `{"manifest_version":"1.0.0","schema_version":"ferralon.normalized_advisory.v2","record_count":2,"records":[
{"identifier":"FERRALON-TEST-0001","path":"FERRALON-TEST-0001.json","output_digest":"sha256:05b1935b9969a04c01692e9242601c91888ff0b88ab7660ecad362f2c8242644"},
{"identifier":"FERRALON-TEST-DATED","path":"2021/12/FERRALON-TEST-DATED.json","output_digest":"sha256:4c15d33aefa531d113fe4b1e441d5e09ea3bbfa9bedfc5550d3b67801992b5ea"}]}`
)

// mutableCorpus copies the two fixture documents into a temp root and writes manifest v1.
func mutableCorpus(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range []string{"FERRALON-TEST-0001.json", "2021/12/FERRALON-TEST-DATED.json"} {
		data, err := os.ReadFile(filepath.Join(advisoryFixtureRoot, rel))
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeManifest(t, root, manifestV1, true)
	return root
}

// writeManifest rewrites root/manifest.json, either by rename (a new file, as a checkout or corpus
// materialization produces) or in place (same file, new size).
func writeManifest(t *testing.T, root, body string, rename bool) {
	t.Helper()
	path := filepath.Join(root, "manifest.json")
	if !rename {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactSource_RefreshPicksUpRewrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rename bool
	}{
		{"replaced by rename", true},
		{"rewritten in place", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := mutableCorpus(t)
			var reads atomic.Int64
			src := countingSource(root, &reads)
			if err := src.Validate(); err != nil {
				t.Fatalf("Validate() = %v", err)
			}
			if _, ok := src.Lookup("FERRALON-TEST-DATED"); ok {
				t.Fatal("v1 served FERRALON-TEST-DATED, want miss")
			}

			writeManifest(t, root, manifestV2, tc.rename)
			if _, ok := src.Lookup("FERRALON-TEST-DATED"); ok {
				t.Fatal("rewrite visible before Refresh: Lookup must not re-check the manifest")
			}
			if err := src.Refresh(); err != nil {
				t.Fatalf("Refresh() after a valid rewrite = %v, want nil", err)
			}
			if _, ok := src.Lookup("FERRALON-TEST-DATED"); !ok {
				t.Fatal("after Refresh, v2's FERRALON-TEST-DATED missed")
			}
			if info, ok := src.Describe(); !ok || info.Records != 2 {
				t.Errorf("Describe() = %+v, %v; want 2 records", info, ok)
			}
			if got := reads.Load(); got != 2 {
				t.Errorf("manifest read %d times, want 2 (initial load + one reload)", got)
			}
		})
	}
}

func TestArtifactSource_CorruptRewriteKeepsLastGoodIndex(t *testing.T) {
	root := mutableCorpus(t)
	writeManifest(t, root, manifestV2, true)
	var reads atomic.Int64
	src := countingSource(root, &reads)
	if err := src.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}

	for _, bad := range []struct{ name, body string }{
		{"unparseable", `{"records": [`},
		{"record_count mismatch", strings.Replace(manifestV2, `"record_count":2`, `"record_count":3`, 1)},
	} {
		t.Run(bad.name, func(t *testing.T) {
			writeManifest(t, root, bad.body, true)
			before := reads.Load()
			err := src.Refresh()
			if err == nil || !strings.Contains(err.Error(), "serving the last good manifest") {
				t.Fatalf("Refresh() after a corrupt rewrite = %v, want a reload error", err)
			}
			if _, ok := src.Lookup("FERRALON-TEST-DATED"); !ok {
				t.Error("corrupt rewrite dropped the last good index")
			}
			if err := src.Validate(); err != nil {
				t.Errorf("Validate() = %v, want nil: the served manifest is still the good one", err)
			}
			if err2 := src.Refresh(); err2 == nil {
				t.Error("second Refresh() on the same corrupt file = nil, want the error to keep surfacing")
			}
			if got := reads.Load() - before; got != 1 {
				t.Errorf("corrupt manifest read %d times across two Refreshes, want 1 (a failed identity is not retried)", got)
			}
		})
	}

	writeManifest(t, root, manifestV1, true)
	if err := src.Refresh(); err != nil {
		t.Fatalf("Refresh() after repairing the manifest = %v, want nil", err)
	}
	if _, ok := src.Lookup("FERRALON-TEST-DATED"); ok {
		t.Error("repaired v1 manifest not picked up")
	}
}

// A source whose first load failed has no good index to protect: a later valid manifest is picked up
// at the next Refresh, and Validate turns healthy.
func TestArtifactSource_RefreshRecoversFromFailedInitialLoad(t *testing.T) {
	root := t.TempDir()
	src := NewArtifactSource(root).(*artifactSource)
	if err := src.Validate(); err == nil {
		t.Fatal("Validate() on an empty root = nil, want error")
	}
	if err := src.Refresh(); err == nil {
		t.Fatal("Refresh() with no manifest = nil, want error")
	}
	corpus := mutableCorpus(t)
	src.root = corpus // same source, now pointing at a materialized corpus
	if err := src.Refresh(); err != nil {
		t.Fatalf("Refresh() once a manifest exists = %v", err)
	}
	if err := src.Validate(); err != nil {
		t.Errorf("Validate() after recovery = %v, want nil", err)
	}
	if _, ok := src.Lookup("FERRALON-TEST-0001"); !ok {
		t.Error("recovered source missed FERRALON-TEST-0001")
	}
}

// advisory_intake is the boundary: running it refreshes the configured source (through the chain),
// so a rewritten manifest is served from the next assessment on.
func TestAdvisoryIntake_RefreshesCorpusAtAssessmentStart(t *testing.T) {
	root := mutableCorpus(t)
	var reads atomic.Int64
	corpus := countingSource(root, &reads)
	chain := NewChainSource(corpus, NewTableSource())
	run := func() {
		t.Helper()
		c := &assessment.Assessment{ID: "a1", Request: assessment.Request{
			Vulnerability: assessment.VulnRef{ID: "FERRALON-TEST-DATED", Source: "test"},
		}}
		if err := (advisoryIntake{src: chain}).Run(context.Background(), c, artifact.NewMemStore()); err != nil {
			t.Fatalf("advisory_intake: %v", err)
		}
	}

	run()
	run()
	if got := reads.Load(); got != 1 {
		t.Fatalf("two assessments over an unchanged manifest read it %d times, want 1", got)
	}
	writeManifest(t, root, manifestV2, true)
	run()
	if _, ok := corpus.Lookup("FERRALON-TEST-DATED"); !ok {
		t.Fatal("assessment start did not pick up the rewritten manifest")
	}
	if got := reads.Load(); got != 2 {
		t.Errorf("manifest read %d times, want 2", got)
	}
}

// KnownIDs and LookupEach read the served index, so a Refresh that swaps in a rewritten manifest
// changes both, and the bulk path keeps agreeing with a Lookup loop across the swap.
func TestArtifactSource_KnownIDsAndLookupEachFollowRefresh(t *testing.T) {
	root := mutableCorpus(t)
	src := NewArtifactSource(root).(*artifactSource)
	ids := []string{"FERRALON-TEST-0001", "FERRALON-TEST-DATED", "FERRALON-TEST-ABSENT"}
	check := func(wantIDs []string) {
		t.Helper()
		if got := src.KnownIDs(); !reflect.DeepEqual(got, wantIDs) {
			t.Errorf("KnownIDs() = %v, want %v", got, wantIDs)
		}
		LookupEach(src, ids, func(id string, facts AdvisoryFacts, ok bool) {
			wantFacts, wantOK := src.Lookup(id)
			if ok != wantOK || !reflect.DeepEqual(facts, wantFacts) {
				t.Errorf("%s: LookupEach = (%v, ok=%v), Lookup = (%v, ok=%v)", id, facts, ok, wantFacts, wantOK)
			}
		})
	}

	check([]string{"FERRALON-TEST-0001"})
	writeManifest(t, root, manifestV2, true)
	if err := src.Refresh(); err != nil {
		t.Fatalf("Refresh() = %v", err)
	}
	check([]string{"FERRALON-TEST-0001", "FERRALON-TEST-DATED"})
	if _, ok := src.Lookup("FERRALON-TEST-DATED"); !ok {
		t.Error("after Refresh, v2's FERRALON-TEST-DATED missed")
	}
}

// Lookup, KnownIDs, and LookupEach racing a rewrite + Refresh see either the old or the new index,
// never a torn one, and the race detector sees no unsynchronized access.
func TestArtifactSource_ConcurrentLookupDuringRefresh(t *testing.T) {
	root := mutableCorpus(t)
	src := NewArtifactSource(root).(*artifactSource)
	if err := src.Validate(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, ok := src.Lookup("FERRALON-TEST-0001"); !ok {
					t.Error("FERRALON-TEST-0001 missed during refresh; it is in every manifest")
					return
				}
				src.Describe()
				if ids := src.KnownIDs(); len(ids) < 1 || len(ids) > 2 || ids[0] != "FERRALON-TEST-0001" {
					t.Errorf("KnownIDs() during refresh = %v, want v1's or v2's id set", ids)
					return
				}
				LookupEach(src, []string{"FERRALON-TEST-0001", "FERRALON-TEST-DATED"}, func(id string, _ AdvisoryFacts, ok bool) {
					if id == "FERRALON-TEST-0001" && !ok {
						t.Error("LookupEach missed FERRALON-TEST-0001 during refresh; it is in every manifest")
					}
				})
			}
		}()
	}
	for i := 0; i < 20; i++ {
		body := manifestV1
		if i%2 == 0 {
			body = manifestV2
		}
		writeManifest(t, root, body, true)
		if err := src.Refresh(); err != nil {
			t.Errorf("Refresh() #%d = %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
}
