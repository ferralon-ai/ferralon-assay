package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// Adjudicated is a person's conclusion about a row, kept apart from comparator_observed (what a tool
// said) and engine_expected (what Assay emits). Every row is seeded `unknown`; only a named reviewer
// sets anything else, and nothing in this program does.
type Adjudicated struct {
	// Status draws on the same values as comparator_observed.
	Status string `yaml:"status"`
	By     string `yaml:"by,omitempty"`
	Date   string `yaml:"date,omitempty"`
	// Evidence is a checkable pointer: file:line in the pinned upstream, a vendor advisory's
	// preconditions, or a reviewed call graph.
	Evidence string `yaml:"evidence,omitempty"`
	Note     string `yaml:"note,omitempty"`
	// BoundTo is the analysis the conclusion was read against; required once Status is not unknown.
	BoundTo *BoundTo `yaml:"bound_to,omitempty"`
}

// BoundTo is the set of analysis inputs a review was made against. A review holds only while every one
// is unchanged: the same path text read under another target, component, symbol evidence or analysis
// is not the same review.
type BoundTo struct {
	// Target is "<target name>@<resolved commit of the scan>".
	Target string `yaml:"target"`
	// Component is the resolved package instance, module@version.
	Component string `yaml:"component"`
	// Symbol is the vulnerable symbol the engine's call path ends at, and SymbolConfidence is the
	// confidence the engine gives that symbol set's provenance (high: osv-declared or curated;
	// moderate: diff-lexed; empty: cna-declared, unrecognized or absent). The report does not carry the
	// advisory's full symbol set or its raw symbol_provenance tag, so these are all it exposes.
	Symbol           string   `yaml:"symbol,omitempty"`
	SymbolConfidence string   `yaml:"symbol_confidence,omitempty"`
	Analysis         Analysis `yaml:"analysis"`
}

// Analysis is the analysis revision: what scanned, with which advisory data, under which toolchain.
type Analysis struct {
	// AssayVersion is the report's provenance.analyzer_version; AssayCommit is the commit the scanner
	// was built from (the scan's meta.json), empty when the scan recorded none.
	AssayVersion  string `yaml:"assay_version"`
	AssayCommit   string `yaml:"assay_commit,omitempty"`
	CorpusRelease string `yaml:"corpus_release"`
	GoVersion     string `yaml:"go_version"`
}

// scanInputs are the analysis inputs of one scan, as the report and its meta.json record them.
type scanInputs struct {
	Commit, AssayVersion, AssayCommit, CorpusRelease, GoVersion string
}

// scanInputsOf reads the inputs of a scan. The corpus release and Go version fall back to the lane's
// pins when meta.json records none: the scan ran under them.
func scanInputsOf(sc *Showcase, r report.Report, m Meta) scanInputs {
	in := scanInputs{Commit: r.Subject.ResolvedCommit, AssayVersion: r.Provenance.AnalyzerVersion,
		AssayCommit: m.AssayCommit, CorpusRelease: m.CorpusRelease, GoVersion: m.GoVersion}
	if sc != nil {
		if in.CorpusRelease == "" {
			in.CorpusRelease = sc.CorpusRelease
		}
		if in.GoVersion == "" {
			in.GoVersion = sc.GoVersion
		}
	}
	return in
}

// boundFor is the BoundTo a review of the row with package pkg would record against this scan; er is
// the engine's row for it, nil when the engine emitted none.
func boundFor(target, pkg string, er *engineRow, in scanInputs) BoundTo {
	b := BoundTo{Target: target + "@" + in.Commit, Component: pkg,
		Analysis: Analysis{AssayVersion: in.AssayVersion, AssayCommit: in.AssayCommit, CorpusRelease: in.CorpusRelease, GoVersion: in.GoVersion}}
	if er != nil && len(er.Path) > 0 {
		b.Symbol, b.SymbolConfidence = er.Path[len(er.Path)-1], er.Confidence
	}
	return b
}

// diff names each field of b that differs from now, as "bound_to.<field>: recorded X, scan has Y".
func (b BoundTo) diff(now BoundTo) []string {
	var out []string
	add := func(field, was, is string) {
		if was != is {
			out = append(out, fmt.Sprintf("bound_to.%s: recorded %q, scan has %q", field, was, is))
		}
	}
	add("target", b.Target, now.Target)
	add("component", b.Component, now.Component)
	add("symbol", b.Symbol, now.Symbol)
	add("symbol_confidence", b.SymbolConfidence, now.SymbolConfidence)
	add("analysis.assay_version", b.Analysis.AssayVersion, now.Analysis.AssayVersion)
	add("analysis.assay_commit", b.Analysis.AssayCommit, now.Analysis.AssayCommit)
	add("analysis.corpus_release", b.Analysis.CorpusRelease, now.Analysis.CorpusRelease)
	add("analysis.go_version", b.Analysis.GoVersion, now.Analysis.GoVersion)
	return out
}

// validate checks a bound_to block carries what a review needs to be held to it.
func (b *BoundTo) validate() error {
	switch {
	case b == nil:
		return fmt.Errorf("a review needs a bound_to block")
	case b.Target == "" || b.Component == "":
		return fmt.Errorf("bound_to needs target and component")
	case b.Analysis.AssayVersion == "" || b.Analysis.CorpusRelease == "" || b.Analysis.GoVersion == "":
		return fmt.Errorf("bound_to.analysis needs assay_version, corpus_release and go_version")
	}
	return nil
}

// reviewed reports whether a person has set the adjudication.
func (a Adjudicated) reviewed() bool { return a.Status != TruthUnknown }

// validateAdjudicated checks the row's adjudication: a known status, and for any conclusion its
// reviewer, date, evidence and the analysis it is bound to. A featured row needs a conclusion.
func (r LedgerRow) validateAdjudicated() error {
	a := r.Adjudicated
	switch {
	case !slices.Contains(truths, a.Status):
		return fmt.Errorf("adjudicated status %q is not one of %s", a.Status, strings.Join(truths, ", "))
	case r.Featured && !a.reviewed():
		return fmt.Errorf("featured: true, but adjudicated.status is unknown: a featured row needs a reviewer's conclusion")
	case !a.reviewed() && (a.By != "" || a.Date != "" || a.Evidence != "" || a.Note != "" || a.BoundTo != nil):
		return fmt.Errorf("adjudicated is unknown but carries a reviewer's fields: set a status or clear them")
	case !a.reviewed():
		return nil
	case a.By == "" || a.Date == "" || a.Evidence == "":
		return fmt.Errorf("adjudicated status %s needs by, date and evidence", a.Status)
	case !validDate(a.Date):
		return fmt.Errorf("adjudicated date %q is not YYYY-MM-DD", a.Date)
	}
	if err := a.BoundTo.validate(); err != nil {
		return fmt.Errorf("adjudicated: %w", err)
	}
	return nil
}

// boundDiffs lists, one line per differing field, every reviewed row whose recorded analysis inputs
// are not the scan's: a path_review past `unreviewed` or an adjudicated conclusion. Rows come in
// ledger order.
func boundDiffs(l Ledger, rows []engineRow, in scanInputs) []string {
	got := map[string]*engineRow{}
	for i, r := range rows {
		got[rowKey(r.Advisory, r.Package, l.Header.Target)] = &rows[i]
	}
	var out []string
	for _, r := range l.Rows {
		now := boundFor(l.Header.Target, r.Package, got[r.Key()], in)
		if pr := r.PathReview; pr != nil && pr.Status != StatusUnreviewed && pr.BoundTo != nil {
			for _, d := range pr.BoundTo.diff(now) {
				out = append(out, fmt.Sprintf("review stale: %s: path_review %s: re-review and reset path_review.status to unreviewed (floorcheck seed -update)", r.Key(), d))
			}
		}
		if a := r.Adjudicated; a.reviewed() && a.BoundTo != nil {
			for _, d := range a.BoundTo.diff(now) {
				out = append(out, fmt.Sprintf("review stale: %s: adjudicated %s: re-adjudicate and reset adjudicated.status to unknown (floorcheck seed -update)", r.Key(), d))
			}
		}
	}
	return out
}
