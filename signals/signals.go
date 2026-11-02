// Package signals loads the EPSS/KEV signals file a run is given, for callers outside this module.
//
// The file is the vulnerability corpus's signals sidecar, signals.json or signals.json.gz. The
// scanner carries no EPSS or KEV data of its own and never fetches FIRST or CISA: a caller of
// trigger.RunBaseline, trigger.RunPRInherit or trigger.RunCVEWatch that wants findings ranked loads
// the file with Load or Parse and hands the result to the request with Feed.
//
// A loaded *Signals answers EPSS(id) and KEV(id), one record's values each; Records, how many
// records the file holds; StaleEPSS, how many of its EPSS values are older than a given age; and
// Digest, the file's signals_digest.
//
// Only signals_version 1.x is read; any other version is an error. A malformed file is an error
// too, never a silent degrade to fewer signals.
//
// EVERY VALUE CARRIES ITS OWN STAMP. An EPSS value carries the model date it came from (EPSS.AsOf),
// and a KEV observation the catalog it was read from (KEV.CatalogVersion, KEV.DateReleased). There
// is no file-wide "as of" date.
//
// LOAD CHECKS THE FILE, NOT WHERE IT CAME FROM. Load and Parse check the file's format, its
// signals_version and its own signals_digest, which they recompute from the payload: a corrupted
// file is refused. They do not check provenance: a file edited and re-stamped with a recomputed
// digest loads. Before loading a file you fetched, verify it against the corpus release's signed
// bundles.json.
//
// THE RUN RECORDS WHICH FILE IT RANKED WITH. trigger.Run* sets Report.Provenance.Intel.SignalsDigest
// (report.IntelProvenance) to the Digest of the *Signals the request was fed, the value Load and
// Parse verified; a request fed none leaves it empty. The caller sets nothing. The rest of
// Provenance.Intel (how the work set was chosen, where the advisory facts came from) is the
// command line's own disclosure and is not set by a library run.
//
// A nil *Signals is valid and holds nothing: a request given nil Signals reports no priority on
// any finding. Signals are ranking context only; nothing that decides a verdict reads them.
package signals

import (
	"io"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/intel"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// Signals is a loaded signals file. A nil *Signals is valid and holds nothing: every lookup misses.
// Safe for concurrent use.
type Signals struct {
	s *intel.Signals
}

// EPSS is one EPSS value with its stamp.
type EPSS struct {
	// Identifier is the signals record the value came from (trimmed, uppercased).
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
	// Identifier is the signals record the observation came from (trimmed, uppercased).
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

// Load reads and validates the signals file at path, and verifies its signals_digest against its
// payload. Plain JSON and gzip-compressed JSON are both accepted, told apart by content rather than
// by name. It does not check where the file came from (see the package doc).
func Load(path string) (*Signals, error) {
	return wrap(intel.Load(path))
}

// Parse reads and validates a signals document from r, which may be gzip-compressed, and verifies
// its signals_digest as Load does.
func Parse(r io.Reader) (*Signals, error) {
	return wrap(intel.Parse(r))
}

func wrap(s *intel.Signals, err error) (*Signals, error) {
	if err != nil {
		return nil, err
	}
	return &Signals{s: s}, nil
}

// in is the scanner's own value, nil for a nil s.
func (s *Signals) in() *intel.Signals {
	if s == nil {
		return nil
	}
	return s.s
}

// EPSS looks up the EPSS value of the record keyed by id, trimmed and uppercased. It is a lookup of
// one record: the run attributes a value to a finding by the advisory's id and aliases.
func (s *Signals) EPSS(id string) (EPSS, bool) {
	e, ok := s.in().EPSS(id)
	// A conversion, not a copy field by field: a field intel adds stops this compiling until it is
	// added here on purpose, or left off.
	return EPSS(e), ok
}

// KEV looks up the KEV observation of the record keyed by id, the same way EPSS does.
func (s *Signals) KEV(id string) (KEV, bool) {
	k, ok := s.in().KEV(id)
	return KEV(k), ok
}

// Records is how many records the file holds.
func (s *Signals) Records() int {
	return s.in().Records()
}

// StaleEPSS counts the file's EPSS values whose AsOf is more than maxAge before now (stale), out of
// all of them (total).
func (s *Signals) StaleEPSS(now time.Time, maxAge time.Duration) (stale, total int) {
	return s.in().StaleEPSS(now, maxAge)
}

// Digest is the file's signals_digest, "" for a nil s. Load and Parse recomputed it from the
// payload and found the file's own value equal, so it names exactly these values. It says nothing
// about who wrote the file (see the package doc). It is the value a Report's
// Provenance.Intel.SignalsDigest names.
func (s *Signals) Digest() string {
	if in := s.in(); in != nil {
		return in.Digest
	}
	return ""
}

// Request is a trigger request that takes signals.
type Request interface {
	*trigger.BaselineRequest | *trigger.PRInheritRequest | *trigger.CVEWatchRequest
}

// Feed gives req the signals its run ranks findings with: s, or none for a nil s. The run records
// s's Digest on its Report as Provenance.Intel.SignalsDigest (see the package doc).
func Feed[R Request](req R, s *Signals) {
	switch r := any(req).(type) {
	case *trigger.BaselineRequest:
		r.Signals = s.in()
	case *trigger.PRInheritRequest:
		r.Signals = s.in()
	case *trigger.CVEWatchRequest:
		r.Signals = s.in()
	}
}
