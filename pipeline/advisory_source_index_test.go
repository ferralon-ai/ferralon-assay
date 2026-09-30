// advisory_source_index_test.go
//
// artifactSource loads its manifest once per source and indexes it by identifier. These tests pin
// that the manifest is read exactly once across many Lookup/Validate/Describe calls, that every
// outcome (hit, missing id, unreadable or invalid manifest) is the same on every call, and that
// concurrent readers are race-free.
package pipeline

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
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
		{"hit", advisoryFixtureRoot, "TEGRON-TEST-0001", true, true},
		{"missing id", advisoryFixtureRoot, "TEGRON-TEST-NOPE", false, true},
		{"digest mismatch", advisoryFixtureRoot, "TEGRON-TEST-BADDIGEST", false, true},
		{"manifest read error", "testdata/advisory_source/does-not-exist", "TEGRON-TEST-0001", false, false},
		{"record_count mismatch", "testdata/advisory_source/badcount", "TEGRON-TEST-BADCOUNT", false, false},
		{"duplicate identifier", "testdata/advisory_source/dupid", "TEGRON-TEST-DUP", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reads atomic.Int64
			src := countingSource(tt.root, &reads)

			if err := src.Validate(); (err == nil) != tt.wantValid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tt.wantValid)
			}
			for i := 0; i < n; i++ {
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
				t.Errorf("manifest read %d times across %d Lookups + Validate + Describe, want 1", got, n)
			}
		})
	}
}

// The index must resolve the same record the manifest names, so a load-once source returns facts
// identical to a fresh source's first Lookup.
func TestArtifactSource_IndexedLookupMatchesFreshSource(t *testing.T) {
	cached := NewArtifactSource(advisoryFixtureRoot)
	cached.Lookup("TEGRON-TEST-NOPE") // force the load through a miss first
	got, ok := cached.Lookup("TEGRON-TEST-0001")
	want, wantOK := NewArtifactSource(advisoryFixtureRoot).Lookup("TEGRON-TEST-0001")
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
				if _, ok := src.Lookup("TEGRON-TEST-0001"); !ok {
					t.Error("concurrent Lookup(TEGRON-TEST-0001) ok=false, want true")
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
