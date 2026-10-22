package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/intel"
)

// defaultSignalsMaxAge is the age past which the run summary warns that the newest EPSS value in
// the signals file is stale (-advisory-signals-max-age).
const defaultSignalsMaxAge = 7 * 24 * time.Hour

// corpusSignalsFile is the signals file a corpus tree keeps at its root.
const corpusSignalsFile = "signals.json"

// resolveSignals resolves the EPSS/KEV signals file this run ranks its findings with, and records
// it (or why there is none) on f. It must run after advisoryCorpusOption, which resolves the corpus
// tree the default comes from.
//
// Precedence: the -advisory-signals flag, then envAdvisorySignals, then — with a corpus DIRECTORY
// configured — that tree's signals.json. A corpus bundle file has no tree to look in.
//
// The scanner carries no signals of its own and never fetches any: with no source, no finding
// carries a Priority and the run summary says so. That is a supported run, not an error.
//
// A file that is named but cannot be read, or that is not a valid signals_version 1.x file, is a
// HARD error — including the corpus default when the tree has one. A broken signals file never
// degrades silently to no priority, any more than a broken corpus degrades to built-in intel. A
// corpus tree with no signals.json at all is not an error: it predates the sidecar, and the
// summary names that as the reason there is no priority.
//
// A STALE file still loads (signalsSummary warns): the stamps on each value say how old it is.
func (f *runFlags) resolveSignals() error {
	f.resolvedSignals, f.signalsOrigin = nil, ""
	if *f.signalsMaxAge <= 0 {
		return fmt.Errorf("-advisory-signals-max-age must be positive, got %s", *f.signalsMaxAge)
	}

	path, origin := *f.signalsPath, "-advisory-signals"
	if path == "" {
		path, origin = os.Getenv(envAdvisorySignals), envAdvisorySignals
	}
	if path == "" && f.corpusTree != "" {
		path, origin = filepath.Join(f.corpusTree, corpusSignalsFile), "the advisory corpus"
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			f.signalsOrigin = fmt.Sprintf("the advisory corpus %s has no %s", f.corpusTree, corpusSignalsFile)
			return nil
		}
	}
	if path == "" {
		return nil
	}

	sig, err := intel.Load(path)
	if err != nil {
		return fmt.Errorf("advisory signals (from %s) are unusable: %w", origin, err)
	}
	f.resolvedSignals, f.signalsOrigin = sig, path
	return nil
}

// signalsSummary is the run summary's one line about signals, as of now: which file the findings
// were ranked with and the date of its newest EPSS value — with a warning, never a failure, when
// that is older than -advisory-signals-max-age — or that there were none, and so no priority.
func (f *runFlags) signalsSummary(now time.Time) string {
	sig := f.resolvedSignals
	if sig == nil {
		why := "no signals source was provided (-advisory-signals, " + envAdvisorySignals + ", or an advisory corpus directory's " + corpusSignalsFile + ")"
		if f.signalsOrigin != "" {
			why = f.signalsOrigin
		}
		return "none — " + why + "; no finding carries EPSS/KEV priority"
	}
	line := fmt.Sprintf("%s (%s, %d record(s))", f.signalsOrigin, sig.Digest, sig.Records())
	newest, ok := sig.NewestEPSSAsOf()
	if !ok {
		return line + "; it carries no EPSS value"
	}
	age := now.Sub(newest)
	days := int(age / (24 * time.Hour))
	line += fmt.Sprintf("; newest EPSS as_of %s (%d day(s) old)", newest.Format(time.DateOnly), days)
	if age > *f.signalsMaxAge {
		line += fmt.Sprintf(" — WARNING: stale, older than the %s bound (-advisory-signals-max-age); loaded anyway, and each value carries its own date", *f.signalsMaxAge)
	}
	return line
}
