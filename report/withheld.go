package report

import (
	"fmt"
	"strings"
)

// Limit is one limit of the analysis that withheld a verdict: its reason code and, for a limit
// scoped to part of the build, the package holding the code the analysis could not see, the place
// inside it, and the packages that code could reach. Package and Targets are package URLs without a
// version. A limit with only a Reason holds for the whole run. A limit with Others stands for that
// many scoped limits of its reason that the row does not list one by one; the scan's partiality
// notes carry the package and path of each.
type Limit struct {
	Reason  string   `json:"reason"`
	Package string   `json:"package,omitempty"`
	Path    string   `json:"path,omitempty"`
	Targets []string `json:"targets,omitempty"`
	Others  int      `json:"others,omitempty"`
}

// limitPhraseTargets is how many of a limit's targets LimitPhrase names before counting the rest.
const limitPhraseTargets = 3

// LimitPhrase renders l on one line: the reason, where the unseen code is, and what it could reach.
func LimitPhrase(l Limit) string {
	var b strings.Builder
	b.WriteString(l.Reason)
	if l.Others > 0 {
		fmt.Fprintf(&b, " (%d scoped limits not listed one by one)", l.Others)
	}
	if l.Package != "" {
		b.WriteString(" in " + l.Package)
	}
	if l.Path != "" {
		b.WriteString(" at " + l.Path)
	}
	if n := len(l.Targets); n > 0 {
		shown := l.Targets
		if n > limitPhraseTargets {
			shown = shown[:limitPhraseTargets]
		}
		b.WriteString(", which could reach " + strings.Join(shown, ", "))
		if n > limitPhraseTargets {
			fmt.Fprintf(&b, " and %d more", n-limitPhraseTargets)
		}
	}
	return b.String()
}

// withheldDetailLimits is how many limits WithheldDetail names before counting the rest.
const withheldDetailLimits = 8

// WithheldDetail is UndeterminedDetail(reason) followed by the limits that withheld the verdict. With
// no limits it is UndeterminedDetail(reason).
func WithheldDetail(reason string, limits []Limit) string {
	detail := UndeterminedDetail(reason)
	if len(limits) == 0 {
		return detail
	}
	shown := limits
	if len(shown) > withheldDetailLimits {
		shown = shown[:withheldDetailLimits]
	}
	phrases := make([]string, len(shown))
	for i, l := range shown {
		phrases[i] = LimitPhrase(l)
	}
	detail += ". It was withheld by: " + strings.Join(phrases, "; ")
	if n := len(limits) - len(shown); n > 0 {
		detail += fmt.Sprintf("; and %d more", n)
	}
	return detail
}
