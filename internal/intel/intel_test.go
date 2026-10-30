package intel

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testDigest is validDoc's signals_digest, computed by the producer's rule (ferralon-ai/intel
// corpus.CanonicalJSON over signals_version, record_count and records), so Load and Parse verify
// it. The other documents here carry it too, and the tests that read them parse them with
// parseUnverified.
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

// parseUnverified parses a signals document as Parse does but leaves its signals_digest unchecked,
// for a test of what else Parse checks or loads.
func parseUnverified(r io.Reader) (*Signals, error) {
	return parse(r, false)
}

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

// TestLookupIsOneRecord: a lookup reads the one record keyed by its id, normalised, whatever the
// identifier form (a GHSA-keyed record matches its own id).
func TestLookupIsOneRecord(t *testing.T) {
	s, err := Parse(strings.NewReader(validDoc))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := s.EPSS(" cve-2021-38561 "); !ok || e.Identifier != "CVE-2021-38561" {
		t.Errorf("EPSS lookup = %+v, %v; want CVE-2021-38561's value", e, ok)
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
	if _, ok := none.Attribute("CVE-2025-8110", nil, nil); ok {
		t.Error("a nil *Signals must attribute nothing")
	}
	if _, ok := none.NewestEPSSAsOf(); ok || none.Records() != 0 {
		t.Error("a nil *Signals holds nothing")
	}
	if stale, total := none.StaleEPSS(time.Now(), time.Hour); stale != 0 || total != 0 {
		t.Error("a nil *Signals holds nothing")
	}
}

// attributionDoc holds a CVE record with EPSS only, a KEV-listed sibling CVE, and a GO roll-up
// standing for both CVEs that carries the sibling's listing.
//
// CVE-2026-1001..1005 are one multi-CVE advisory's aliases: 1001 carries a stamped "not listed", 1002
// is KEV-listed with the same EPSS value, 1003 agrees with 1001 in every value and stamp, 1004
// differs from 1001 only in its EPSS score, and 1005 only in its EPSS as_of. 1006 differs from 1001
// only in its EPSS percentile (a sourced 0), and 1007 from 1006 only in having no percentile. 1008
// differs from 1001 only in KEV listed (neither states a date_added), 1009 only in its KEV
// catalog_version, and 1010 differs from 1002 only in its KEV date_added.
const attributionDoc = `{"signals_version": "1.0.0", "record_count": 13, "signals_digest": "` + testDigest + `",
  "records": [
    {"identifier": "CVE-2023-39325", "epss": {"score": 0.03, "as_of": "2026-08-01"}},
    {"identifier": "CVE-2023-44487", "epss": {"score": 0.99, "as_of": "2026-08-11"},
     "kev": {"listed": true, "date_added": "2023-10-10", "catalog_version": "2026.08.11", "date_released": "2026-08-11T18:59:43Z"}},
    {"identifier": "GO-2023-2102", "epss": {"score": 0.99, "as_of": "2026-08-11"},
     "kev": {"listed": true, "date_added": "2023-10-10", "catalog_version": "2026.08.11", "date_released": "2026-08-11T18:59:43Z"}},
    {"identifier": "CVE-2026-1001", "epss": {"score": 0.02, "percentile": 0.5, "as_of": "2026-10-18"},
     "kev": {"listed": false, "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}},
    {"identifier": "CVE-2026-1002", "epss": {"score": 0.02, "percentile": 0.5, "as_of": "2026-10-18"},
     "kev": {"listed": true, "date_added": "2026-10-01", "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}},
    {"identifier": "CVE-2026-1003", "epss": {"score": 0.02, "percentile": 0.5, "as_of": "2026-10-18"},
     "kev": {"listed": false, "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}},
    {"identifier": "CVE-2026-1004", "epss": {"score": 0.7, "percentile": 0.5, "as_of": "2026-10-18"},
     "kev": {"listed": false, "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}},
    {"identifier": "CVE-2026-1005", "epss": {"score": 0.02, "percentile": 0.5, "as_of": "2026-10-11"},
     "kev": {"listed": false, "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}},
    {"identifier": "CVE-2026-1006", "epss": {"score": 0.02, "percentile": 0, "as_of": "2026-10-18"},
     "kev": {"listed": false, "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}},
    {"identifier": "CVE-2026-1007", "epss": {"score": 0.02, "as_of": "2026-10-18"},
     "kev": {"listed": false, "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}},
    {"identifier": "CVE-2026-1008", "epss": {"score": 0.02, "percentile": 0.5, "as_of": "2026-10-18"},
     "kev": {"listed": true, "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}},
    {"identifier": "CVE-2026-1009", "epss": {"score": 0.02, "percentile": 0.5, "as_of": "2026-10-18"},
     "kev": {"listed": false, "catalog_version": "2026.10.20", "date_released": "2026-10-19T18:00:00Z"}},
    {"identifier": "CVE-2026-1010", "epss": {"score": 0.02, "percentile": 0.5, "as_of": "2026-10-18"},
     "kev": {"listed": true, "date_added": "2026-10-02", "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}}]}`

// TestAttribute pins the join's three rules: the advisory's own record and only it; nothing through
// an alias for a CVE-keyed advisory; otherwise a CVE alias with a record that no other advisory of
// the run names, and nothing when any two of its CVE aliases' records disagree — claimed or not.
func TestAttribute(t *testing.T) {
	s, err := Parse(strings.NewReader(sealed(t, attributionDoc)))
	if err != nil {
		t.Fatal(err)
	}
	got := func(id string, aliases []string, claims *Claims) string {
		m, ok := s.Attribute(id, aliases, claims)
		if !ok {
			return "none"
		}
		return fmt.Sprintf("%s epss=%v kev=%v", m.Identifier, m.HasEPSS, m.HasKEV)
	}
	both := new(Claims)
	both.Add("GHSA-4374-p667-p6c8", "CVE-2023-39325", "GO-2023-2102")
	both.Add("CVE-2023-39325", "GO-2023-2102")
	listedClaimed := new(Claims)
	listedClaimed.Add("GO-2026-0001", "CVE-2026-1001", "CVE-2026-1002")
	listedClaimed.Add("CVE-2026-1002")
	agreeingClaimed := new(Claims)
	agreeingClaimed.Add("GO-2026-0001", "CVE-2026-1001", "CVE-2026-1003")
	agreeingClaimed.Add("CVE-2026-1001")
	for _, c := range []struct {
		name, id string
		aliases  []string
		claims   *Claims
		want     string
	}{
		// Rule 1: its own record, and only it — the KEV it lacks is not filled in from the GO alias.
		{"own record only", "cve-2023-39325", []string{"GO-2023-2102"}, nil, "CVE-2023-39325 epss=true kev=false"},
		{"own GO record", "GO-2023-2102", []string{"CVE-2023-39325", "CVE-2023-44487"}, nil, "GO-2023-2102 epss=true kev=true"},
		// Rule 2: a CVE with no record of its own takes nothing — not the GO roll-up, not a CVE alias.
		{"CVE, GO roll-up alias", "CVE-2099-0001", []string{"GO-2023-2102"}, nil, "none"},
		{"CVE, CVE alias", "CVE-2099-0001", []string{"CVE-2023-44487"}, nil, "none"},
		// Rule 3: a non-CVE advisory takes its first CVE alias with a record, never a roll-up alias.
		{"GHSA, CVE alias", "GHSA-4374-p667-p6c8", []string{"GO-2023-2102", "CVE-2099-0002", "CVE-2023-39325"}, nil, "CVE-2023-39325 epss=true kev=false"},
		{"GHSA, roll-up alias only", "GHSA-4374-p667-p6c8", []string{"GO-2023-2102"}, nil, "none"},
		{"GHSA, alias another advisory names", "GHSA-4374-p667-p6c8", []string{"CVE-2023-39325", "GO-2023-2102"}, both, "none"},
		{"house id, no alias", "FERRALON-APP-SSRF-0001", nil, nil, "none"},
		// Rule 3 with several CVE aliases that have records: they must agree, whatever their order.
		{"only the second CVE is KEV-listed", "GO-2026-0001", []string{"CVE-2026-1001", "CVE-2026-1002"}, nil, "none"},
		{"only the first CVE is KEV-listed", "GO-2026-0001", []string{"CVE-2026-1002", "CVE-2026-1001"}, nil, "none"},
		{"CVEs differ in EPSS score", "GO-2026-0001", []string{"CVE-2026-1001", "CVE-2026-1004"}, nil, "none"},
		{"CVEs differ in EPSS as_of", "GO-2026-0001", []string{"CVE-2026-1001", "CVE-2026-1005"}, nil, "none"},
		// A sourced percentile of 0 and no percentile at all are different values, not the same 0.
		{"CVEs differ only in percentile presence", "GO-2026-0001", []string{"CVE-2026-1006", "CVE-2026-1007"}, nil, "none"},
		{"CVEs differ only in EPSS percentile", "GO-2026-0001", []string{"CVE-2026-1001", "CVE-2026-1006"}, nil, "none"},
		{"CVEs differ only in KEV listed", "GO-2026-0001", []string{"CVE-2026-1001", "CVE-2026-1008"}, nil, "none"},
		{"CVEs differ only in KEV catalog_version", "GO-2026-0001", []string{"CVE-2026-1001", "CVE-2026-1009"}, nil, "none"},
		{"CVEs differ only in KEV date_added", "GO-2026-0001", []string{"CVE-2026-1002", "CVE-2026-1010"}, nil, "none"},
		{"CVEs agree", "GO-2026-0001", []string{"GHSA-xxxx-yyyy-zzzz", "CVE-2026-1001", "CVE-2026-1003"}, nil, "CVE-2026-1001 epss=true kev=true"},
		// A CVE another advisory names is never the source, but it still takes part in the check.
		{"a disagreeing CVE another advisory names", "GO-2026-0001", []string{"CVE-2026-1001", "CVE-2026-1002"}, listedClaimed, "none"},
		{"a disagreeing CVE another advisory names, listed first", "GO-2026-0001", []string{"CVE-2026-1002", "CVE-2026-1001"}, listedClaimed, "none"},
		{"an agreeing CVE another advisory names", "GO-2026-0001", []string{"CVE-2026-1001", "CVE-2026-1003"}, agreeingClaimed, "CVE-2026-1003 epss=true kev=true"},
		{"a disagreeing CVE with no record", "GO-2026-0001", []string{"CVE-2026-1001", "CVE-2099-0003"}, nil, "CVE-2026-1001 epss=true kev=true"},
	} {
		if g := got(c.id, c.aliases, c.claims); g != c.want {
			t.Errorf("%s: Attribute(%s, %v) = %s, want %s", c.name, c.id, c.aliases, g, c.want)
		}
	}
}

// TestClaims: an identifier is claimed by another advisory when one names it as its id or an alias;
// an advisory never claims against itself, and ids are normalised.
func TestClaims(t *testing.T) {
	c := new(Claims)
	c.Add("CVE-2023-39325", "GO-2023-2102")
	c.Add(" cve-2023-39325 ", "ghsa-4374-p667-p6c8")
	if c.ClaimedByOther("GO-2023-2102", "CVE-2023-39325") || c.ClaimedByOther("GHSA-4374-P667-P6C8", "CVE-2023-39325") {
		t.Error("an advisory's own identifiers are not claimed by another")
	}
	c.Add("CVE-2023-44487", "go-2023-2102")
	if !c.ClaimedByOther("GO-2023-2102", "CVE-2023-39325") || !c.ClaimedByOther("CVE-2023-39325", "CVE-2023-44487") {
		t.Error("an identifier another advisory names, as an alias or as its id, is claimed by it")
	}
	var none *Claims
	if none.ClaimedByOther("GO-2023-2102", "CVE-2023-39325") {
		t.Error("a nil *Claims names nothing")
	}
}

// TestStaleEPSS counts the values more than the bound older than now, out of all EPSS values; KEV
// observations are not counted, and a value exactly at the bound is not stale.
func TestStaleEPSS(t *testing.T) {
	s, err := Parse(strings.NewReader(validDoc)) // EPSS as_of 2026-10-18, 2026-10-19, 2026-10-01
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		maxAge       time.Duration
		stale, total int
	}{
		{7 * 24 * time.Hour, 1, 3},
		{2 * 24 * time.Hour, 1, 3}, // 2026-10-18 is exactly 2 days old: at the bound, not past it
		{36 * time.Hour, 2, 3},
		{12 * time.Hour, 3, 3},
		{30 * 24 * time.Hour, 0, 3},
	} {
		if stale, total := s.StaleEPSS(now, c.maxAge); stale != c.stale || total != c.total {
			t.Errorf("StaleEPSS(%s) = %d/%d, want %d/%d", c.maxAge, stale, total, c.stale, c.total)
		}
	}
}

// TestEPSSPercentileZeroIsSourced: a sourced percentile of 0 (CVE-2026-50268's real record) loads as
// sourced, told apart from a record that carries no percentile.
func TestEPSSPercentileZeroIsSourced(t *testing.T) {
	s, err := parseUnverified(strings.NewReader(`{"signals_version": "1.0.0", "record_count": 2, "signals_digest": "` + testDigest + `",
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
		_, err := parseUnverified(strings.NewReader(doc))
		if err == nil {
			t.Errorf("signals_version %s loaded; want it rejected", v)
			continue
		}
		if !strings.Contains(err.Error(), "signals_version") {
			t.Errorf("signals_version %s: error %q does not name signals_version", v, err)
		}
	}
	// A 2.x document is refused for its version even when the rest of it has another shape.
	_, err := parseUnverified(strings.NewReader(`{"signals_version": "2.0.0", "records": {"CVE-1": {}}}`))
	if err == nil || !strings.Contains(err.Error(), `unsupported signals_version "2.0.0"`) {
		t.Errorf("2.x document: err = %v, want an unsupported-version error", err)
	}
	if _, err := parseUnverified(strings.NewReader(`{"records": []}`)); err == nil || !strings.Contains(err.Error(), "signals_version is missing") {
		t.Errorf("missing version: err = %v", err)
	}
	if _, err := parseUnverified(strings.NewReader(strings.Replace(validDoc, `"1.0.0"`, `"1.4.2"`, 1))); err != nil {
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
		if s, err := parseUnverified(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: loaded %d records; want an error", name, s.Records())
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("Load of a missing file must error")
	}
}
