package github

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// entrypointsShown caps the roots listed per kind; the rest are counted, and the report holds all.
const entrypointsShown = 5

// entrypointLines renders one line per lane that reported its entry points (report.Entrypoints):
// whether the set was inferred, inferred as an application's (naming the mains it rests on, with the
// statement that reads the build as a library instead), or declared, the roots it analysed by kind, and any declared
// selector that matched nothing. Under an override it also shows what the lane inferred before the
// override (only the kinds the override changed) and the "!" selectors that removed something.
// Returns nil when no lane reported a set. Every name comes from the scanned repository or the
// caller, so each renders inside a code span.
func entrypointLines(r report.Report) []string {
	out := make([]string, 0, len(r.Entrypoints))
	for _, e := range r.Entrypoints {
		var b strings.Builder
		b.WriteString(plainName(e.Lane) + ": ")
		unlisted := entryUnlisted(e)
		switch {
		case e.Source == plugin.LibraryEntrypointsSourceDeclared:
			fmt.Fprintf(&b, "declared, resolved as %s", mdCode(e.Input))
		case e.Source == plugin.LibraryEntrypointsSourceMains:
			b.WriteString("treated as an application, nothing declared: its main packages are the entry points")
			if mains := e.Effective[plugin.EntryKindMain]; len(mains) > 0 {
				b.WriteString(" " + entrypointRoots(mains))
			}
		case unlisted:
			b.WriteString("nothing declared")
		default:
			b.WriteString("inferred, nothing declared")
		}
		if unlisted {
			b.WriteString("; entry points not listed because dependency code was not read.")
			out = append(out, b.String())
			continue
		}
		kinds := make([]string, 0, len(e.Effective))
		for k := range e.Effective {
			if k == plugin.EntryKindMain && e.Source == plugin.LibraryEntrypointsSourceMains {
				continue // named with the application reading above
			}
			kinds = append(kinds, k)
		}
		slices.Sort(kinds)
		for _, k := range kinds {
			b.WriteString("; " + entrypointKind(k, e.Effective[k]))
		}
		if entryOverridden(e) {
			// A kind the record does not report as analysed is outside the override's reach (the go
			// lane, under an override, reports only its library set), so it is not "changed".
			for _, k := range slices.Sorted(maps.Keys(e.Inferred)) {
				if eff, ok := e.Effective[k]; ok && !slices.Equal(e.Inferred[k], eff) {
					b.WriteString("; inferred before the override: " + entrypointKind(k, e.Inferred[k]))
				}
			}
			if len(e.Denied) > 0 {
				denied := make([]string, 0, len(e.Denied))
				for _, s := range e.Denied {
					denied = append(denied, mdCode(s))
				}
				b.WriteString("; removed by: " + strings.Join(denied, ", "))
			}
		}
		// Only an unmatched include withholds verdicts; an unmatched "!" exclude removes nothing.
		var includes, excludes []string
		for _, s := range e.Unmatched {
			if strings.HasPrefix(s, "!") {
				excludes = append(excludes, mdCode(s))
			} else {
				includes = append(includes, mdCode(s))
			}
		}
		if len(includes) > 0 {
			fmt.Fprintf(&b, "; matched nothing, so verdicts resting on it are withheld: %s", strings.Join(includes, ", "))
		}
		if len(excludes) > 0 {
			fmt.Fprintf(&b, "; excluded nothing: %s", strings.Join(excludes, ", "))
		}
		if e.Source == plugin.LibraryEntrypointsSourceMains {
			b.WriteString("; library mode: " + mdCode("go:library=."))
		}
		b.WriteString(".")
		out = append(out, b.String())
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// entryOverridden reports whether the caller's declaration shaped the record: a declared source, or
// an input that says something other than auto.
func entryOverridden(e plugin.EntryRootRecord) bool {
	return e.Source == plugin.LibraryEntrypointsSourceDeclared || (e.Input != "" && e.Input != plugin.LibraryEntrypointsAuto)
}

// entryUnlisted reports a js record the lane emitted without reading dependency code: it reports no
// inferred set and every kind in Effective is empty, which says nothing was listed, not that there
// are none. Only js records are checked: an empty go set (a declared none) is a real answer.
func entryUnlisted(e plugin.EntryRootRecord) bool {
	if e.Lane != plugin.EntryLaneJS || e.Inferred != nil {
		return false
	}
	for _, roots := range e.Effective {
		if len(roots) > 0 {
			return false
		}
	}
	return true
}

func entrypointKind(kind string, roots []string) string {
	label := plainName(kind)
	if kind == plugin.EntryKindLibrary {
		label = "library packages callable from outside the build"
	}
	if len(roots) == 0 {
		return label + ": none"
	}
	return label + " " + entrypointRoots(roots)
}

// entrypointRoots renders roots as their count and the first entrypointsShown of them.
func entrypointRoots(roots []string) string {
	shown := make([]string, 0, min(len(roots), entrypointsShown))
	for _, s := range roots[:min(len(roots), entrypointsShown)] {
		shown = append(shown, mdCode(s))
	}
	line := fmt.Sprintf("(%d): %s", len(roots), strings.Join(shown, ", "))
	if n := len(roots) - len(shown); n > 0 {
		line += fmt.Sprintf(" and %d more", n)
	}
	return line
}

const entrypointsLead = "**Entry points.** Beyond the build's own programs, the analysis treated these as entry points; set the `entrypoints` input to change them:"

// plainName renders a lane or kind name as plain text when it is a bare lowercase word, as every
// name the lanes emit is, and inside a code span otherwise.
func plainName(s string) string {
	for _, r := range s {
		if r < 'a' || r > 'z' {
			return mdCode(s)
		}
	}
	if s == "" {
		return mdCode(s)
	}
	return s
}

// entrypointsBlock renders the lanes' entry points for the Tier-0 job-summary panel, or "" when no
// lane reported a set.
func entrypointsBlock(r report.Report) string {
	lines := entrypointLines(r)
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(entrypointsLead + "\n\n")
	for _, l := range lines {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	b.WriteString("\n")
	return b.String()
}

// entrypointsCallout renders the lanes' entry points as a [!NOTE] alert beside the assumptions one,
// or "" when no lane reported a set.
func entrypointsCallout(r report.Report) string {
	lines := entrypointLines(r)
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("> [!NOTE]\n")
	b.WriteString("> " + entrypointsLead + "\n")
	b.WriteString(">\n")
	for _, l := range lines {
		fmt.Fprintf(&b, "> - %s\n", l)
	}
	b.WriteString("\n")
	return b.String()
}
