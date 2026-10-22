package intel

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testDigest is validDoc's signals_digest, computed by the producer's rule (ferralon-ai/intel
// corpus.CanonicalJSON over signals_version, record_count and records), so Load verifies it. The
// other documents here carry it too; Parse does not check a digest.
const testDigest = "sha256:0aaac15ef7792202e9932ea1c08d160eda5e3edfc997157759c9702518a99ec1"

// validDoc is a hand-written signals 1.x document: an EPSS-only record, a listed KEV record with an
// EPSS value, a stamped not-listed KEV record, and a GHSA-keyed record. Values are illustrative.
const validDoc = `{
  "signals_version": "1.0.0",
  "generated_at": "2026-10-20T06:00:00Z",
  "record_count": 4,
  "signals_digest": "` + testDigest + `",
  "records": [
    {"identifier": "CVE-2021-38561", "epss": {"score": 0.0123, "percentile": 0.456, "as_of": "2026-10-18"}},
    {"identifier": "CVE-2025-8110",
     "epss": {"score": 0.91, "percentile": 0.99, "as_of": "2026-10-19"},
     "kev": {"listed": true, "date_added": "2025-07-28", "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00.000Z"}},
    {"identifier": "CVE-2024-55947",
     "kev": {"listed": false, "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00.000Z"}},
    {"identifier": "GHSA-aaaa-bbbb-cccc", "epss": {"score": 0.2, "as_of": "2026-10-01"}}
  ]
}`

func writeFixture(t *testing.T, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func gzipped(t *testing.T, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// damagedGzip gzips body and corrupts the trailing CRC, which a reader sees only at end of stream.
func damagedGzip(t *testing.T, body string) string {
	t.Helper()
	b := gzipped(t, body)
	b[len(b)-8] ^= 0xff
	return string(b)
}

// TestLoadValid1x loads the same 1.x document as plain JSON and as gzip, and checks that every value
// comes back with its own stamp.
func TestLoadValid1x(t *testing.T) {
	for name, body := range map[string][]byte{
		"signals.json":    []byte(validDoc),
		"signals.json.gz": gzipped(t, validDoc),
	} {
		t.Run(name, func(t *testing.T) {
			s, err := Load(writeFixture(t, name, body))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if s.Version != "1.0.0" || s.Digest != testDigest || s.Records() != 4 {
				t.Errorf("envelope = %q %q %d, want 1.0.0 %s 4", s.Version, s.Digest, s.Records(), testDigest)
			}
			e, ok := s.EPSS("CVE-2021-38561")
			if !ok || e.Score != 0.0123 || e.Percentile != 0.456 || !e.HasPercentile || e.AsOf != "2026-10-18" {
				t.Errorf("EPSS(CVE-2021-38561) = %+v, %v", e, ok)
			}
			k, ok := s.KEV("CVE-2025-8110")
			want := KEV{Identifier: "CVE-2025-8110", Listed: true, DateAdded: "2025-07-28", CatalogVersion: "2026.10.19", DateReleased: "2026-10-19T18:00:00.000Z"}
			if !ok || k != want {
				t.Errorf("KEV(CVE-2025-8110) = %+v, %v; want %+v", k, ok, want)
			}
			// A stamped negative is an observation, not a miss.
			k, ok = s.KEV("CVE-2024-55947")
			if !ok || k.Listed || k.CatalogVersion != "2026.10.19" {
				t.Errorf("KEV(CVE-2024-55947) = %+v, %v; want a stamped not-listed observation", k, ok)
			}
			if _, ok := s.EPSS("CVE-2024-55947"); ok {
				t.Error("CVE-2024-55947 carries no EPSS value, but the lookup found one")
			}
			newest, ok := s.NewestEPSSAsOf()
			if !ok || !newest.Equal(time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)) {
				t.Errorf("NewestEPSSAsOf = %v, %v; want 2026-10-19", newest, ok)
			}
		})
	}
}

// TestLookupFollowsIDOrder: the first id the file has a value for wins, ids are normalised, and any
// identifier form joins (a GHSA-keyed record matches its own id).
func TestLookupFollowsIDOrder(t *testing.T) {
	s, err := Parse(strings.NewReader(validDoc))
	if err != nil {
		t.Fatal(err)
	}
	e, ok := s.EPSS("GO-2021-0113", " cve-2021-38561 ", "CVE-2025-8110")
	if !ok || e.Identifier != "CVE-2021-38561" {
		t.Errorf("EPSS lookup = %+v, %v; want the first matching id CVE-2021-38561", e, ok)
	}
	if e, ok := s.EPSS("ghsa-aaaa-bbbb-cccc"); !ok || e.Percentile != 0 || e.HasPercentile || e.AsOf != "2026-10-01" {
		t.Errorf("EPSS(GHSA) = %+v, %v; want a score with no percentile", e, ok)
	}
	if _, ok := s.KEV("CVE-2021-38561"); ok {
		t.Error("KEV found a value for a record that has only EPSS")
	}
	var none *Signals
	if _, ok := none.EPSS("CVE-2021-38561"); ok {
		t.Error("a nil *Signals must miss every lookup")
	}
	if _, ok := none.KEV("CVE-2025-8110"); ok {
		t.Error("a nil *Signals must miss every lookup")
	}
	if _, ok := none.NewestEPSSAsOf(); ok || none.Records() != 0 {
		t.Error("a nil *Signals holds nothing")
	}
}

// TestEPSSPercentileZeroIsSourced: a sourced percentile of 0 (CVE-2026-50268's real record) loads as
// sourced, told apart from a record that carries no percentile.
func TestEPSSPercentileZeroIsSourced(t *testing.T) {
	s, err := Parse(strings.NewReader(`{"signals_version": "1.0.0", "record_count": 2, "signals_digest": "` + testDigest + `",
	  "records": [
	    {"identifier": "CVE-2026-50268", "epss": {"score": 0.00047, "percentile": 0, "as_of": "2026-08-02"}},
	    {"identifier": "GHSA-pppp-qqqq-rrrr", "epss": {"score": 0.00047, "as_of": "2026-08-02"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := EPSS{Identifier: "CVE-2026-50268", Score: 0.00047, HasPercentile: true, AsOf: "2026-08-02"}
	if e, ok := s.EPSS("CVE-2026-50268"); !ok || e != want {
		t.Errorf("EPSS(CVE-2026-50268) = %+v, %v; want the sourced zero percentile %+v", e, ok, want)
	}
	want = EPSS{Identifier: "GHSA-PPPP-QQQQ-RRRR", Score: 0.00047, AsOf: "2026-08-02"}
	if e, ok := s.EPSS("GHSA-pppp-qqqq-rrrr"); !ok || e != want {
		t.Errorf("EPSS(GHSA-pppp-qqqq-rrrr) = %+v, %v; want no percentile %+v", e, ok, want)
	}
}

// TestParseRejectsUnsupportedVersion: only signals_version 1.x loads.
func TestParseRejectsUnsupportedVersion(t *testing.T) {
	for _, v := range []string{`"2.0.0"`, `"0.9.0"`, `"1"`, `"1.0"`, `"v1.0.0"`, `""`, `1`} {
		doc := strings.Replace(validDoc, `"1.0.0"`, v, 1)
		_, err := Parse(strings.NewReader(doc))
		if err == nil {
			t.Errorf("signals_version %s loaded; want it rejected", v)
			continue
		}
		if !strings.Contains(err.Error(), "signals_version") {
			t.Errorf("signals_version %s: error %q does not name signals_version", v, err)
		}
	}
	// A 2.x document is refused for its version even when the rest of it has another shape.
	_, err := Parse(strings.NewReader(`{"signals_version": "2.0.0", "records": {"CVE-1": {}}}`))
	if err == nil || !strings.Contains(err.Error(), `unsupported signals_version "2.0.0"`) {
		t.Errorf("2.x document: err = %v, want an unsupported-version error", err)
	}
	if _, err := Parse(strings.NewReader(`{"records": []}`)); err == nil || !strings.Contains(err.Error(), "signals_version is missing") {
		t.Errorf("missing version: err = %v", err)
	}
	if _, err := Parse(strings.NewReader(strings.Replace(validDoc, `"1.0.0"`, `"1.4.2"`, 1))); err != nil {
		t.Errorf("signals_version 1.4.2 must load: %v", err)
	}
}

// TestParseRejectsMalformed: a file that breaks the contract errors as a whole. Nothing is loaded
// from it, so a broken file never degrades silently to fewer signals.
func TestParseRejectsMalformed(t *testing.T) {
	rec := func(r string) string {
		return `{"signals_version": "1.0.0", "record_count": 1, "signals_digest": "` + testDigest + `", "records": [` + r + `]}`
	}
	cases := map[string]string{
		"truncated":             validDoc[:len(validDoc)/2],
		"not json":              "signals",
		"trailing data":         validDoc + "{}",
		"gzip, damaged tail":    damagedGzip(t, validDoc),
		"bad gzip":              "\x1f\x8bnot-gzip",
		"record_count mismatch": strings.Replace(validDoc, `"record_count": 4`, `"record_count": 5`, 1),
		"record_count missing":  strings.Replace(validDoc, `"record_count": 4,`, ``, 1),
		"digest missing":        `{"signals_version": "1.0.0", "record_count": 0, "records": []}`,
		"digest malformed":      strings.Replace(validDoc, testDigest, "sha256:abc", 1),
		"records missing":       `{"signals_version": "1.0.0", "record_count": 0, "signals_digest": "` + testDigest + `"}`,
		"records not an array":  `{"signals_version": "1.0.0", "record_count": 0, "signals_digest": "` + testDigest + `", "records": {}}`,
		"identifier missing":    rec(`{"epss": {"score": 0.1, "as_of": "2026-10-01"}}`),
		"duplicate identifier":  `{"signals_version": "1.0.0", "record_count": 2, "signals_digest": "` + testDigest + `", "records": [{"identifier": "CVE-1", "epss": {"score": 0.1, "as_of": "2026-10-01"}}, {"identifier": "cve-1", "epss": {"score": 0.2, "as_of": "2026-10-01"}}]}`,
		"neither signal":        rec(`{"identifier": "CVE-1"}`),
		"epss without as_of":    rec(`{"identifier": "CVE-1", "epss": {"score": 0.1}}`),
		"epss bad as_of":        rec(`{"identifier": "CVE-1", "epss": {"score": 0.1, "as_of": "yesterday"}}`),
		"epss without score":    rec(`{"identifier": "CVE-1", "epss": {"as_of": "2026-10-01"}}`),
		"epss score > 1":        rec(`{"identifier": "CVE-1", "epss": {"score": 1.5, "as_of": "2026-10-01"}}`),
		"epss percentile < 0":   rec(`{"identifier": "CVE-1", "epss": {"score": 0.1, "percentile": -0.1, "as_of": "2026-10-01"}}`),
		"kev without catalog":   rec(`{"identifier": "CVE-1", "kev": {"listed": true, "date_released": "2026-10-01T00:00:00Z"}}`),
		"kev without released":  rec(`{"identifier": "CVE-1", "kev": {"listed": false, "catalog_version": "2026.10.01"}}`),
		"kev without listed":    rec(`{"identifier": "CVE-1", "kev": {"catalog_version": "2026.10.01", "date_released": "2026-10-01T00:00:00Z"}}`),
		"epss score wrong type": rec(`{"identifier": "CVE-1", "epss": {"score": "high", "as_of": "2026-10-01"}}`),
		"kev listed wrong type": rec(`{"identifier": "CVE-1", "kev": {"listed": "yes", "catalog_version": "2026.10.01", "date_released": "2026-10-01T00:00:00Z"}}`),
	}
	for name, doc := range cases {
		if s, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: loaded %d records; want an error", name, s.Records())
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("Load of a missing file must error")
	}
}
