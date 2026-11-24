package github

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// entrypointsShown caps the roots listed per kind; the rest are counted, and the report holds all.
const entrypointsShown = 5

// entrypointLines renders one line per lane that reported its entry points (report.Entrypoints):
// whether the set was inferred or declared, the roots it analysed by kind, and any declared
// selector that matched nothing. Returns nil when no lane reported a set. Every name comes from the
// scanned repository or the caller, so each renders inside a code span.
func entrypointLines(r report.Report) []string {
	out := make([]string, 0, len(r.Entrypoints))
	for _, e := range r.Entrypoints {
		var b strings.Builder
		b.WriteString(e.Lane + ": ")
		if e.Source == plugin.LibraryEntrypointsSourceDeclared {
			fmt.Fprintf(&b, "declared by the `entrypoints` input %s", mdCode(e.Input))
		} else {
			b.WriteString("inferred, nothing declared")
		}
		kinds := make([]string, 0, len(e.Effective))
		for k := range e.Effective {
			kinds = append(kinds, k)
		}
		slices.Sort(kinds)
		for _, k := range kinds {
			b.WriteString("; " + entrypointKind(k, e.Effective[k]))
		}
		if len(e.Unmatched) > 0 {
			um := make([]string, len(e.Unmatched))
			for i, s := range e.Unmatched {
				um[i] = mdCode(s)
			}
			fmt.Fprintf(&b, "; matched nothing: %s", strings.Join(um, ", "))
		}
		b.WriteString(".")
		out = append(out, b.String())
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func entrypointKind(kind string, roots []string) string {
	if len(roots) == 0 {
		return kind + ": none"
	}
	shown := make([]string, 0, min(len(roots), entrypointsShown))
	for _, s := range roots[:min(len(roots), entrypointsShown)] {
		shown = append(shown, mdCode(s))
	}
	line := fmt.Sprintf("%s (%d): %s", kind, len(roots), strings.Join(shown, ", "))
	if n := len(roots) - len(shown); n > 0 {
		line += fmt.Sprintf(" and %d more", n)
	}
	return line
}

const entrypointsLead = "**Entry points.** The analysis treated these as where execution can start; set the `entrypoints` input to override them:"

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
