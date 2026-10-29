package main

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/intel"
	"github.com/ferralon-ai/ferralon-assay/report"
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

// noSignalsPriority ends signalsSummary's line for a run that loaded no signals file.
const noSignalsPriority = "; no finding carries EPSS/KEV priority"

// signalsSummary is the run summary's one line about signals, as of now: which file the findings
// were ranked with, the date of its newest EPSS value, and how many of its EPSS values are older
// than -advisory-signals-max-age — with a warning, never a failure, when the newest is older than
// that bound or over half of them are — or that there were none, and so no priority.
//
// The newest value alone hides a file that is mostly old: one fresh value keeps it young while
// nearly every other value is weeks behind it. The share is what says how old the ranking is.
func (f *runFlags) signalsSummary(now time.Time) string {
	sig := f.resolvedSignals
	if sig == nil {
		why := "no signals source was provided (-advisory-signals, " + envAdvisorySignals + ", or an advisory corpus directory's " + corpusSignalsFile + ")"
		if f.signalsOrigin != "" {
			why = f.signalsOrigin
		}
		return "none — " + why + noSignalsPriority
	}
	line := fmt.Sprintf("%s (%s, %d record(s))", f.signalsOrigin, sig.Digest, sig.Records())
	newest, ok := sig.NewestEPSSAsOf()
	if !ok {
		return line + "; it carries no EPSS value"
	}
	maxAge, bound := *f.signalsMaxAge, formatBound(*f.signalsMaxAge)
	age := now.Sub(newest)
	days := int(age / (24 * time.Hour))
	line += fmt.Sprintf("; newest EPSS as_of %s (%d day(s) old)", newest.Format(time.DateOnly), days)
	stale, total := sig.StaleEPSS(now, maxAge)
	line += fmt.Sprintf("; EPSS: %d/%d (%d%%) older than %s", stale, total, percentOf(stale, total), bound)
	const loaded = " (-advisory-signals-max-age); loaded anyway, and each value carries its own date"
	switch {
	case age > maxAge:
		line += " — WARNING: stale, even the newest EPSS value is older than the " + bound + " bound" + loaded
	case stale*2 > total:
		line += " — WARNING: stale, over half the EPSS values are older than the " + bound + " bound" + loaded
	}
	return line
}

// publishedSignalsSummary is signalsSummary checked against rep, the Report as published. The two
// name the same file unless a conflicting write merged this run's rows with another run's: the
// merged Report then names no file when a kept row came from a run that did not share this one's,
// or the other run's file when that file ranked every kept row. Either way the line says so rather
// than reading as "the published findings were ranked with this run's file". When this run loaded no
// file but a published row carries a Priority, that row was ranked by another run's file — named by
// the Report, or not when the merge cleared it — so the line drops its "no finding carries EPSS/KEV
// priority" tail.
func (f *runFlags) publishedSignalsSummary(rep *report.Report, now time.Time) string {
	line := f.signalsSummary(now)
	var loaded, published string
	if f.resolvedSignals != nil {
		loaded = f.resolvedSignals.Digest
	}
	if rep.Provenance.Intel != nil {
		published = rep.Provenance.Intel.SignalsDigest
	}
	if published == loaded && (loaded != "" || !anyPriority(rep)) {
		return line
	}
	if loaded == "" {
		line = strings.TrimSuffix(line, noSignalsPriority)
	}
	if published == "" {
		return line + "; merged with another run's rows on a conflicting write, so the published Report names no signals file"
	}
	return line + "; merged with another run's rows on a conflicting write, so the published Report names that run's signals file instead (" + published + ")"
}

// anyPriority reports whether any of rep's findings carries a Priority.
func anyPriority(rep *report.Report) bool {
	for i := range rep.Advisories {
		if rep.Advisories[i].Priority != nil {
			return true
		}
	}
	return false
}

// formatBound renders a max-age bound in whole days when it is one ("7d"), else as a duration.
func formatBound(d time.Duration) string {
	const day = 24 * time.Hour
	if d%day == 0 {
		return fmt.Sprintf("%dd", d/day)
	}
	return d.String()
}

// percentOf is n as a whole percentage of total, rounded, but never 0% for a non-zero n or 100% for
// an n short of total: a share that is not all (or none) never prints as if it were.
func percentOf(n, total int) int {
	if total == 0 {
		return 0
	}
	p := int(math.Round(100 * float64(n) / float64(total)))
	switch {
	case p == 0 && n > 0:
		return 1
	case p == 100 && n < total:
		return 99
	}
	return p
}
