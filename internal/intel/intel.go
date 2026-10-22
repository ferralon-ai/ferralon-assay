// Package intel loads the EPSS/KEV signals file a run is GIVEN — the vulnerability corpus's signals
// sidecar, signals.json or signals.json.gz — and looks advisories up in it.
//
// The scanner carries no EPSS or KEV data of its own and never fetches FIRST or CISA. Signals reach
// a run only as a provided input (a path, or a corpus tree's signals.json); a run given none reports
// no priority at all, rather than a months-old value dressed as current.
//
// EVERY VALUE CARRIES ITS OWN STAMP. The producer emits an EPSS value only with the model date it
// came from (as_of), and a KEV observation only with the catalog it was read from (catalog_version,
// date_released); there is no file-wide "as of" date. This package keeps each stamp attached to its
// value, and rejects a file that breaks that contract instead of loading part of it: a malformed
// file is an error, never a silent degrade to fewer signals.
//
// It is ranking context only. Nothing that decides a verdict reads it (inv. 5).
//
// The format is the corpus's "signals sidecar" (vulnerability-corpus CONSUMING.md):
//
//	{"signals_version": "1.0.0", "generated_at": "…", "record_count": N, "signals_digest": "sha256:…",
//	 "records": [{"identifier": "CVE-…",
//	              "epss": {"score": 0.01715, "percentile": 0.74691, "as_of": "2026-07-27"},
//	              "kev":  {"listed": true, "date_added": "2022-01-28",
//	                       "catalog_version": "2026.07.27", "date_released": "2026-07-27T19:00:15.8632Z"}}]}
package intel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

// EPSS is one EPSS value with its stamp.
type EPSS struct {
	// Identifier is the signals record the value came from (normalised).
	Identifier string
	// Score is FIRST.org's 0..1 probability of exploitation in the 30 days after AsOf.
	Score float64
	// Percentile is the score's rank among all scored CVEs in the same model run (0..1); 0 when
	// the producer did not source one. A sourced 0 is a real percentile: HasPercentile tells the two
	// apart.
	Percentile float64
	// HasPercentile is whether the producer sourced Percentile, zero included.
	HasPercentile bool
	// AsOf is the EPSS model date (YYYY-MM-DD) the score and percentile come from. Always set.
	AsOf string
}

// KEV is one CISA KEV observation with its stamp. Listed false means "not in the catalog named by
// CatalogVersion, released at DateReleased" — never "not listed today".
type KEV struct {
	// Identifier is the signals record the observation came from (normalised).
	Identifier string
	// Listed is whether the identifier appeared in that catalog.
	Listed bool
	// DateAdded is the date CISA added it; set only when Listed and the producer stated it.
	DateAdded string
	// CatalogVersion is CISA's version string for the catalog read. Always set.
	CatalogVersion string
	// DateReleased is CISA's release timestamp for that catalog version. Always set.
	DateReleased string
}

// Signals is a loaded signals file. A nil *Signals is valid and holds nothing: every lookup misses.
type Signals struct {
	// Version is the file's signals_version (1.x).
	Version string
	// Digest is the file's signals_digest, as the producer wrote it. It pins the payload; it is not
	// recomputed here (the Action verifies the release asset's sha256 before the scan).
	Digest string
	// GeneratedAt is when the producer wrote the file. It is NOT the freshness of any value.
	GeneratedAt string

	records int
	epss    map[string]EPSS
	kev     map[string]KEV
	newest  time.Time // the newest EPSS as_of; zero when the file carries no EPSS value
}

// supportedVersion matches the signals_version majors this scanner reads: 1.x.
var supportedVersion = regexp.MustCompile(`^1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// digestPattern is the shape of a signals_digest.
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Load reads and validates the signals file at path. Plain JSON and gzip-compressed JSON are both
// accepted, told apart by content rather than by name.
func Load(path string) (*Signals, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("signals file: %w", err)
	}
	defer f.Close()
	s, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("signals file %s: %w", path, err)
	}
	return s, nil
}

// Parse reads and validates a signals document from r, which may be gzip-compressed.
func Parse(r io.Reader) (*Signals, error) {
	br := bufio.NewReader(r)
	if magic, _ := br.Peek(2); bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("open gzip stream: %w", err)
		}
		defer gz.Close()
		r = gz
	} else {
		r = br
	}

	// Every top-level field is decoded raw first, so a document from another major version is
	// refused for its version rather than for whatever shape the rest of it has.
	var env struct {
		SignalsVersion json.RawMessage `json:"signals_version"`
		GeneratedAt    json.RawMessage `json:"generated_at"`
		RecordCount    json.RawMessage `json:"record_count"`
		SignalsDigest  json.RawMessage `json:"signals_digest"`
		Records        json.RawMessage `json:"records"`
	}
	// Read to the end before decoding: that is what makes gzip verify its checksum, and Unmarshal
	// (unlike a stream decoder) refuses anything after the document — a damaged file errors.
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("not a signals document: %w", err)
	}
	var version string
	if env.SignalsVersion == nil {
		return nil, fmt.Errorf("signals_version is missing")
	}
	if err := json.Unmarshal(env.SignalsVersion, &version); err != nil {
		return nil, fmt.Errorf("signals_version is not a string: %w", err)
	}
	if !supportedVersion.MatchString(version) {
		return nil, fmt.Errorf("unsupported signals_version %q: this scanner reads signals_version 1.x", version)
	}

	var (
		generatedAt, digest string
		count               int
		records             []wireRecord
	)
	if env.GeneratedAt != nil {
		if err := json.Unmarshal(env.GeneratedAt, &generatedAt); err != nil {
			return nil, fmt.Errorf("generated_at: %w", err)
		}
	}
	if err := json.Unmarshal(env.SignalsDigest, &digest); env.SignalsDigest == nil || err != nil || !digestPattern.MatchString(digest) {
		return nil, fmt.Errorf("signals_digest %s is not a sha256 digest (sha256:<64 hex>)", orMissing(env.SignalsDigest))
	}
	if env.RecordCount == nil {
		return nil, fmt.Errorf("record_count is missing")
	}
	if err := json.Unmarshal(env.RecordCount, &count); err != nil {
		return nil, fmt.Errorf("record_count: %w", err)
	}
	if env.Records == nil || bytes.Equal(env.Records, []byte("null")) {
		return nil, fmt.Errorf("records is missing")
	}
	if err := json.Unmarshal(env.Records, &records); err != nil {
		return nil, fmt.Errorf("records: %w", err)
	}
	if count != len(records) {
		return nil, fmt.Errorf("record_count is %d but the file holds %d records", count, len(records))
	}

	s := &Signals{
		Version:     version,
		Digest:      digest,
		GeneratedAt: generatedAt,
		records:     len(records),
		epss:        make(map[string]EPSS),
		kev:         make(map[string]KEV),
	}
	seen := make(map[string]struct{}, len(records))
	for i, rec := range records {
		if err := s.add(rec, seen); err != nil {
			return nil, fmt.Errorf("records[%d]: %w", i, err)
		}
	}
	return s, nil
}

type wireRecord struct {
	Identifier string `json:"identifier"`
	EPSS       *struct {
		Score      *float64 `json:"score"`
		Percentile *float64 `json:"percentile"`
		AsOf       string   `json:"as_of"`
	} `json:"epss"`
	KEV *struct {
		Listed         *bool  `json:"listed"`
		DateAdded      string `json:"date_added"`
		CatalogVersion string `json:"catalog_version"`
		DateReleased   string `json:"date_released"`
	} `json:"kev"`
}

// add validates one record and indexes its values. A value without its stamp is an error: the
// producer never publishes one, so a file carrying one is not a signals file this scanner trusts.
func (s *Signals) add(rec wireRecord, seen map[string]struct{}) error {
	id := normalise(rec.Identifier)
	if id == "" {
		return fmt.Errorf("identifier is missing")
	}
	if _, dup := seen[id]; dup {
		return fmt.Errorf("identifier %s appears more than once", id)
	}
	seen[id] = struct{}{}
	if rec.EPSS == nil && rec.KEV == nil {
		return fmt.Errorf("%s carries neither epss nor kev", id)
	}

	if e := rec.EPSS; e != nil {
		if e.AsOf == "" {
			return fmt.Errorf("%s: epss has no as_of stamp", id)
		}
		asOf, err := parseAsOf(e.AsOf)
		if err != nil {
			return fmt.Errorf("%s: epss as_of %q: %w", id, e.AsOf, err)
		}
		if e.Score == nil {
			return fmt.Errorf("%s: epss has no score", id)
		}
		if *e.Score < 0 || *e.Score > 1 {
			return fmt.Errorf("%s: epss score %v is outside [0,1]", id, *e.Score)
		}
		v := EPSS{Identifier: id, Score: *e.Score, AsOf: e.AsOf}
		if e.Percentile != nil {
			if *e.Percentile < 0 || *e.Percentile > 1 {
				return fmt.Errorf("%s: epss percentile %v is outside [0,1]", id, *e.Percentile)
			}
			v.Percentile, v.HasPercentile = *e.Percentile, true
		}
		s.epss[id] = v
		if asOf.After(s.newest) {
			s.newest = asOf
		}
	}

	if k := rec.KEV; k != nil {
		if k.CatalogVersion == "" || k.DateReleased == "" {
			return fmt.Errorf("%s: kev has no catalog stamp (catalog_version and date_released are both required)", id)
		}
		if k.Listed == nil {
			return fmt.Errorf("%s: kev has no listed value", id)
		}
		v := KEV{Identifier: id, Listed: *k.Listed, CatalogVersion: k.CatalogVersion, DateReleased: k.DateReleased}
		if v.Listed {
			v.DateAdded = k.DateAdded
		}
		s.kev[id] = v
	}
	return nil
}

// orMissing renders a raw JSON value for an error message, or "missing" when it is absent.
func orMissing(raw json.RawMessage) string {
	if raw == nil {
		return "missing"
	}
	return string(raw)
}

// parseAsOf reads an EPSS as_of: a date, or (tolerated) a full RFC 3339 timestamp.
func parseAsOf(v string) (time.Time, error) {
	if t, err := time.Parse(time.DateOnly, v); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339Nano, v)
}

// Records is how many records the file holds.
func (s *Signals) Records() int {
	if s == nil {
		return 0
	}
	return s.records
}

// NewestEPSSAsOf is the newest EPSS as_of in the file, and false when it carries no EPSS value. It
// is the bound on how fresh any EPSS value here can be; each value still carries its own stamp.
func (s *Signals) NewestEPSSAsOf() (time.Time, bool) {
	if s == nil || s.newest.IsZero() {
		return time.Time{}, false
	}
	return s.newest, true
}

// EPSS looks up the EPSS value for the first of ids the file has one for. Callers pass an
// advisory's id followed by its aliases; ids are normalised (trimmed, uppercased) before lookup.
// Safe for concurrent use.
func (s *Signals) EPSS(ids ...string) (EPSS, bool) {
	if s == nil {
		return EPSS{}, false
	}
	for _, id := range ids {
		if v, ok := s.epss[normalise(id)]; ok {
			return v, true
		}
	}
	return EPSS{}, false
}

// KEV looks up the KEV observation for the first of ids the file has one for, the same way EPSS
// does. The returned Identifier names the record it came from, so a caller can tell which id the
// observation is about. Safe for concurrent use.
func (s *Signals) KEV(ids ...string) (KEV, bool) {
	if s == nil {
		return KEV{}, false
	}
	for _, id := range ids {
		if v, ok := s.kev[normalise(id)]; ok {
			return v, true
		}
	}
	return KEV{}, false
}

// normalise trims whitespace and uppercases an advisory id.
func normalise(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}
