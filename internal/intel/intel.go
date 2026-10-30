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
// file is an error, never a silent degrade to fewer signals. Load and Parse also recompute the
// file's signals_digest from its payload and refuse a file whose stated digest does not match, so
// the digest a report names is one this scan verified, not one the file merely asserts. They also
// refuse every key the digest cannot see: the digest hashes each object's exact keys, while the
// loader matches keys to fields under case folding and keeps the last of a repeated key. So a case
// variant of a known field ("Score" for "score"), two keys equal under case folding, and an exact
// duplicate key are each an error, at any depth, and every value loaded is one the digest covered.
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
// It is public through package signals (signals/), whose wrapper forwards Load, Parse, EPSS, KEV,
// Records, StaleEPSS and Digest, and converts EPSS and KEV: a change to any of those is a public one.
type Signals struct {
	// Version is the file's signals_version (1.x).
	Version string
	// Digest is the file's signals_digest. Load and Parse set it only after recomputing it from the
	// payload and finding the file's own value equal, so it names exactly the values loaded. That
	// proves the file self-consistent, not who wrote it: a file edited and re-stamped with a
	// recomputed digest loads.
	Digest string
	// GeneratedAt is when the producer wrote the file. It is NOT the freshness of any value.
	GeneratedAt string

	records  int
	epss     map[string]EPSS
	kev      map[string]KEV
	newest   time.Time   // the newest EPSS as_of; zero when the file carries no EPSS value
	epssAsOf []time.Time // every EPSS value's as_of, for StaleEPSS
}

// supportedVersion matches the signals_version majors this scanner reads: 1.x.
var supportedVersion = regexp.MustCompile(`^1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// digestPattern is the shape of a signals_digest.
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Load reads and validates the signals file at path, and verifies its signals_digest: a file whose
// stated digest is not the digest of its payload is refused, never loaded in part or in place of
// another source. Plain JSON and gzip-compressed JSON are both accepted, told apart by content
// rather than by name.
func Load(path string) (*Signals, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("signals file: %w", err)
	}
	defer f.Close()
	s, err := parse(f, true)
	if err != nil {
		return nil, fmt.Errorf("signals file %s: %w", path, err)
	}
	return s, nil
}

// Parse reads and validates a signals document from r, which may be gzip-compressed, and verifies
// its signals_digest as Load does: a document whose stated digest is not the digest of its payload
// is refused.
func Parse(r io.Reader) (*Signals, error) {
	return parse(r, true)
}

// parse is Parse. With verify false it checks everything but signals_digest, which only this
// package's own tests of those other checks ask for; nothing outside the package can.
//
// The digest is taken over the records as the file holds them, and the values are loaded from the
// same records, one record at a time: each is decoded once generically (the digest's view) and
// once into wireRecord (the loader's), and a record whose keys the two would read differently is
// refused (decodeChecked), so no value loads that the digest did not cover.
func parse(r io.Reader, verify bool) (*Signals, error) {
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

	// readEnvelope reads to the end of the stream, which is what makes gzip verify its checksum, and
	// refuses anything after the document: a damaged file errors. Every top-level field is kept raw
	// first, so a document from another major version is refused for its version rather than for
	// whatever shape the rest of it has.
	env, err := readEnvelope(json.NewDecoder(r))
	if err != nil {
		return nil, fmt.Errorf("not a signals document: %w", err)
	}
	var version string
	if env.signalsVersion != nil {
		if err := json.Unmarshal(env.signalsVersion, &version); err != nil {
			return nil, fmt.Errorf("signals_version is not a string: %w", err)
		}
		if !supportedVersion.MatchString(version) {
			return nil, fmt.Errorf("unsupported signals_version %q: this scanner reads signals_version 1.x", version)
		}
	}
	if env.keyErr != nil {
		return nil, env.keyErr
	}
	if env.signalsVersion == nil {
		return nil, fmt.Errorf("signals_version is missing")
	}

	var (
		generatedAt, digest string
		count               int
	)
	if env.generatedAt != nil {
		if err := json.Unmarshal(env.generatedAt, &generatedAt); err != nil {
			return nil, fmt.Errorf("generated_at: %w", err)
		}
	}
	if err := json.Unmarshal(env.signalsDigest, &digest); env.signalsDigest == nil || err != nil || !digestPattern.MatchString(digest) {
		return nil, fmt.Errorf("signals_digest %s is not a sha256 digest (sha256:<64 hex>)", orMissing(env.signalsDigest))
	}
	if env.recordCount == nil {
		return nil, fmt.Errorf("record_count is missing")
	}
	if err := json.Unmarshal(env.recordCount, &count); err != nil {
		return nil, fmt.Errorf("record_count: %w", err)
	}
	switch env.records {
	case recordsMissing:
		return nil, fmt.Errorf("records is missing")
	case recordsNotArray:
		return nil, fmt.Errorf("records is not an array")
	}
	if count != len(env.recordValues) {
		return nil, fmt.Errorf("record_count is %d but the file holds %d records", count, len(env.recordValues))
	}

	s := &Signals{
		Version:     version,
		Digest:      digest,
		GeneratedAt: generatedAt,
		records:     count,
		epss:        make(map[string]EPSS),
		kev:         make(map[string]KEV),
	}
	var hash *payloadHash
	if verify {
		hash = newPayloadHash(count)
	}
	seen := make(map[string]struct{}, count)
	for i, raw := range env.recordValues {
		v, err := decodeChecked(raw, recordFields)
		if err != nil {
			return nil, fmt.Errorf("records[%d] (%s): %w", i, recordName(raw), err)
		}
		var rec wireRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("records[%d]: %w", i, err)
		}
		if err := s.add(rec, seen); err != nil {
			return nil, fmt.Errorf("records[%d]: %w", i, err)
		}
		if hash != nil {
			if err := hash.record(v); err != nil {
				return nil, fmt.Errorf("records[%d]: canonicalize: %w", i, err)
			}
		}
		env.recordValues[i] = nil // loaded and hashed: nothing reads it again
	}
	if hash != nil {
		got, err := hash.sum(version)
		if err != nil {
			return nil, fmt.Errorf("canonicalize the signals payload: %w", err)
		}
		if got != digest {
			return nil, fmt.Errorf("signals_digest mismatch: the file states %s but its payload hashes to %s; refusing it", shortDigest(digest), shortDigest(got))
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
		s.epssAsOf = append(s.epssAsOf, asOf)
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

// shortDigest is a digest's short form for a message: the algorithm and the first 12 hex digits.
func shortDigest(d string) string {
	if len(d) > len("sha256:")+12 {
		return d[:len("sha256:")+12] + "…"
	}
	return d
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

// StaleEPSS counts the file's EPSS values whose as_of is more than maxAge before now (stale), out of
// all of them (total). The newest as_of only bounds how fresh a value CAN be; this is how many are
// old, which is what a reader of the ranking needs when most of a file is weeks behind its newest
// value.
func (s *Signals) StaleEPSS(now time.Time, maxAge time.Duration) (stale, total int) {
	if s == nil {
		return 0, 0
	}
	for _, asOf := range s.epssAsOf {
		if now.Sub(asOf) > maxAge {
			stale++
		}
	}
	return stale, len(s.epssAsOf)
}

// EPSS looks up the EPSS value of the record keyed by id, normalised (trimmed, uppercased). It is
// a lookup of one record, not a join: attributing a value to an advisory goes through Attribute.
// Safe for concurrent use.
func (s *Signals) EPSS(id string) (EPSS, bool) {
	if s == nil {
		return EPSS{}, false
	}
	v, ok := s.epss[normalise(id)]
	return v, ok
}

// KEV looks up the KEV observation of the record keyed by id, the same way EPSS does. Safe for
// concurrent use.
func (s *Signals) KEV(id string) (KEV, bool) {
	if s == nil {
		return KEV{}, false
	}
	v, ok := s.kev[normalise(id)]
	return v, ok
}

// has reports whether the file holds a record keyed by the normalised id.
func (s *Signals) has(id string) bool {
	_, e := s.epss[id]
	_, k := s.kev[id]
	return e || k
}

// Claims indexes the advisories of one run by every identifier they name — each advisory's id and
// each of its aliases — so that Attribute never takes the record of an alias some OTHER advisory
// also names. A run's claims are its work set: every advisory the run was asked about, by its id
// and the aliases its record lists, and every row its report holds, fresh or inherited. The zero
// value is empty and ready to use; a nil *Claims names nothing.
type Claims struct {
	by map[string]map[string]struct{} // identifier → the ids of the advisories naming it
}

// Add records one advisory: its id and its aliases.
func (c *Claims) Add(id string, aliases ...string) {
	owner := normalise(id)
	if owner == "" {
		return
	}
	if c.by == nil {
		c.by = make(map[string]map[string]struct{})
	}
	for _, ident := range append([]string{id}, aliases...) {
		ident = normalise(ident)
		if ident == "" {
			continue
		}
		if c.by[ident] == nil {
			c.by[ident] = make(map[string]struct{})
		}
		c.by[ident][owner] = struct{}{}
	}
}

// ClaimedByOther reports whether an advisory other than the one with id names ident, as its id or
// as an alias.
func (c *Claims) ClaimedByOther(ident, id string) bool {
	if c == nil {
		return false
	}
	owner := normalise(id)
	for other := range c.by[normalise(ident)] {
		if other != owner {
			return true
		}
	}
	return false
}

// Match is the one signals record attributed to an advisory. Identifier names the record; a value
// the record does not carry is absent, never filled in from another record.
type Match struct {
	Identifier string
	EPSS       EPSS
	HasEPSS    bool
	KEV        KEV
	HasKEV     bool
}

// Attribute is the join of an advisory to the signals file: which ONE record, if any, its EPSS and
// KEV values come from. EPSS and KEV score CVEs, while a GO, PYSEC, RUSTSEC or GHSA record is one
// advisory's roll-up and may stand for several CVEs at once, so the rule only takes a record that
// is about this advisory's own vulnerability:
//
//  1. The record keyed by the advisory's own id, when the file has one — that record and only that
//     one. A value it lacks stays absent; no alias fills it in.
//  2. Otherwise, if the advisory is keyed by a CVE: nothing. Its signal is the record under its own
//     CVE, and the file has none. An alias record — a GO roll-up that may carry a sibling CVE's KEV
//     listing, or another CVE — is never taken in its place.
//  3. Otherwise (a GO-, GHSA-, PYSEC-, RUSTSEC- or house-keyed advisory with no record of its own):
//     the records of its CVE aliases. Every CVE alias that has a record takes part, and their
//     records must agree: the same KEV observation, or none, and the same EPSS value, or none, each
//     with the same stamp. When any two disagree, nothing: which of the advisory's CVEs its signal
//     is cannot be told from the file, and taking one would hand it CVE-A's stamped "not listed"
//     while its CVE-B is KEV-listed. An alias some other advisory in claims (the run's work set)
//     names — as that advisory's id or one of its aliases — still takes part in that check, but its
//     record is never the one taken. When they agree, the first alias no other advisory names is
//     taken, and which one does not change a value; when every alias with a record is claimed,
//     nothing.
//
// A refused match is honest absence: ok is false and the row gets no priority, never a guess.
// Safe for concurrent use.
func (s *Signals) Attribute(id string, aliases []string, claims *Claims) (Match, bool) {
	if s == nil {
		return Match{}, false
	}
	own := normalise(id)
	if s.has(own) {
		return s.match(own), true
	}
	if isCVE(own) {
		return Match{}, false
	}
	var m, first Match
	found, voted := false, false
	for _, alias := range aliases {
		a := normalise(alias)
		if a == own || !isCVE(a) || !s.has(a) {
			continue
		}
		c := s.match(a)
		if !voted {
			first, voted = c, true
		} else if !first.sameValues(c) {
			return Match{}, false
		}
		if !found && !claims.ClaimedByOther(a, own) {
			m, found = c, true
		}
	}
	return m, found
}

// sameValues reports whether two matches carry the same values with the same stamps, whichever
// record each came from. Whether a percentile was sourced is part of the EPSS value: a sourced 0 and
// no percentile disagree.
func (m Match) sameValues(o Match) bool {
	if m.HasEPSS != o.HasEPSS || m.HasKEV != o.HasKEV {
		return false
	}
	me, oe, mk, ok := m.EPSS, o.EPSS, m.KEV, o.KEV
	me.Identifier, oe.Identifier, mk.Identifier, ok.Identifier = "", "", "", ""
	return me == oe && mk == ok
}

// match assembles the values of the record keyed by the normalised id.
func (s *Signals) match(id string) Match {
	m := Match{Identifier: id}
	m.EPSS, m.HasEPSS = s.epss[id]
	m.KEV, m.HasKEV = s.kev[id]
	return m
}

// isCVE reports whether a normalised identifier is a CVE id.
func isCVE(id string) bool {
	return strings.HasPrefix(id, "CVE-")
}

// normalise trims whitespace and uppercases an advisory id.
func normalise(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}
