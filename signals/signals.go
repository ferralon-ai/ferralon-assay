// Package signals loads the EPSS/KEV signals file a run is given, for callers outside this module.
//
// The file is the vulnerability corpus's signals sidecar, signals.json or signals.json.gz. The
// scanner carries no EPSS or KEV data of its own and never fetches FIRST or CISA: a caller of
// trigger.RunBaseline, trigger.RunPRInherit or trigger.RunCVEWatch that wants findings ranked loads
// the file with Load or Parse and passes the result as the request's Signals field.
//
// Only signals_version 1.x is read; any other version is an error. A malformed file is an error
// too, never a silent degrade to fewer signals.
//
// EVERY VALUE CARRIES ITS OWN STAMP. An EPSS value carries the model date it came from (AsOf), and
// a KEV observation the catalog it was read from (CatalogVersion, DateReleased). There is no
// file-wide "as of" date; GeneratedAt is when the producer wrote the file, not how fresh any value is.
//
// A nil *Signals is valid and holds nothing: a request given nil Signals reports no priority on
// any finding. Signals are ranking context only; nothing that decides a verdict reads them.
//
// The types here are aliases of the scanner's own, so a value loaded here is the very value the
// trigger requests take.
package signals

import (
	"io"

	"github.com/ferralon-ai/ferralon-assay/internal/intel"
)

// Signals is a loaded signals file. A nil *Signals is valid and holds nothing: every lookup misses.
type Signals = intel.Signals

// EPSS is one EPSS value with its stamp.
type EPSS = intel.EPSS

// KEV is one CISA KEV observation with its stamp. Listed false means "not in the catalog named by
// CatalogVersion, released at DateReleased" — never "not listed today".
type KEV = intel.KEV

// Load reads and validates the signals file at path. Plain JSON and gzip-compressed JSON are both
// accepted, told apart by content rather than by name.
func Load(path string) (*Signals, error) {
	return intel.Load(path)
}

// Parse reads and validates a signals document from r, which may be gzip-compressed.
func Parse(r io.Reader) (*Signals, error) {
	return intel.Parse(r)
}
