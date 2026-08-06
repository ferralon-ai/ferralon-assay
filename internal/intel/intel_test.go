package intel

import (
	"encoding/json"
	"math"
	"testing"
)

const epssScoreTolerance = 1e-5

// wantEPSS reads a CVE's score/percentile directly from the embedded EPSS snapshot via the
// production parser, so assertions track whatever snapshot is embedded rather than a value that
// drifts out from under the test on every refresh-intel.sh run (same rationale as TestKEVFirstEntry
// below; EPSS scores/percentiles for a fixed CVE shift as the global model recomputes).
func wantEPSS(t *testing.T, cveID string) EPSSScore {
	t.Helper()
	s, ok := parseEPSS()[normalise(cveID)]
	if !ok {
		t.Fatalf("%s not found in the embedded EPSS snapshot", cveID)
	}
	return s
}

func TestEPSSKnownCVE(t *testing.T) {
	want := wantEPSS(t, "CVE-1999-0001")
	s, ok := EPSS("CVE-1999-0001")
	if !ok {
		t.Fatal("EPSS: expected ok=true for CVE-1999-0001")
	}
	if math.Abs(s.Score-want.Score) > epssScoreTolerance {
		t.Errorf("EPSS Score: got %v, want ~%v", s.Score, want.Score)
	}
	if math.Abs(s.Percentile-want.Percentile) > epssScoreTolerance {
		t.Errorf("EPSS Percentile: got %v, want ~%v", s.Percentile, want.Percentile)
	}
}

func TestKEVFirstEntry(t *testing.T) {
	// Read the first CVE from the embedded KEV JSON directly to avoid
	// hardcoding a value that may drift with snapshot refreshes.
	var cat struct {
		Vulnerabilities []struct {
			CVEID     string `json:"cveID"`
			DateAdded string `json:"dateAdded"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(kevJSON, &cat); err != nil {
		t.Fatalf("failed to unmarshal kev.json for test: %v", err)
	}
	if len(cat.Vulnerabilities) == 0 {
		t.Fatal("KEV catalog is empty")
	}
	first := cat.Vulnerabilities[0]
	e, ok := KEV(first.CVEID)
	if !ok {
		t.Fatalf("KEV: expected ok=true for %s", first.CVEID)
	}
	if e.DateAdded != first.DateAdded {
		t.Errorf("KEV DateAdded: got %q, want %q", e.DateAdded, first.DateAdded)
	}
}

func TestEPSSAliasResolution(t *testing.T) {
	// GHSA prefix skipped; CVE alias resolves.
	want := wantEPSS(t, "CVE-1999-0001")
	s, ok := EPSS("GHSA-xxxx-yyyy-zzzz", "CVE-1999-0001")
	if !ok {
		t.Fatal("EPSS alias: expected ok=true via CVE alias")
	}
	if math.Abs(s.Score-want.Score) > epssScoreTolerance {
		t.Errorf("EPSS alias Score: got %v, want ~%v", s.Score, want.Score)
	}
}

func TestEPSSNonCVENoMatch(t *testing.T) {
	// A GO advisory with no CVE alias must return ok=false.
	_, ok := EPSS("GO-2021-0001")
	if ok {
		t.Fatal("EPSS: expected ok=false for GO-2021-0001 with no CVE alias")
	}
}

func TestEPSSCaseInsensitive(t *testing.T) {
	want := wantEPSS(t, "CVE-1999-0001")
	s, ok := EPSS("cve-1999-0001")
	if !ok {
		t.Fatal("EPSS case: expected ok=true for lowercase cve-1999-0001")
	}
	if math.Abs(s.Score-want.Score) > epssScoreTolerance {
		t.Errorf("EPSS case Score: got %v, want ~%v", s.Score, want.Score)
	}
}

func TestConsts(t *testing.T) {
	if SnapshotDate == "" {
		t.Error("SnapshotDate must be non-empty")
	}
	if EPSSModelVersion == "" {
		t.Error("EPSSModelVersion must be non-empty")
	}
}
