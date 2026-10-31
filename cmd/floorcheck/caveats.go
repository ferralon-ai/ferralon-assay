package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// Caveats is floor/caveats.json: which machine-readable reason a report carries stands for which
// caveat of the language capability matrix. The tally it drives is informational: it never fails
// a repository and never reaches the alert.
type Caveats struct {
	Mappings []CaveatMapping `json:"mappings"`
	// Structural are caveats no reason code names, because they hold for every scan of the
	// language. The summary lists them as always applying.
	Structural []StructuralCaveat `json:"structural,omitempty"`
}

// CaveatMapping maps one reason to one caveat.
type CaveatMapping struct {
	// Reason is the code exactly as report.json carries it: a partiality[].reason, an
	// advisories[].undetermined_reason, or a package's partial_reason.
	Reason string `json:"reason"`
	// Language is the target language the mapping holds for, or "any".
	Language string `json:"language"`
	// RunWide restricts the mapping to the run-wide form of the reason: a partiality note that
	// names no package and no path. A scoped note, a row's reason or a package's reason then
	// does not fire the caveat. False fires it on every occurrence.
	RunWide bool   `json:"run_wide"`
	Caveat  string `json:"caveat"`
	// DefinedIn is the Go file, relative to the repository root, that declares the reason's
	// constant. TestShippedCaveatReasons evaluates the file's constants to keep the mapping honest.
	DefinedIn string `json:"defined_in"`
	Note      string `json:"note,omitempty"`
}

// StructuralCaveat is a caveat that holds for every scan of its language.
type StructuralCaveat struct {
	Caveat   string `json:"caveat"`
	Language string `json:"language"`
}

// anyLanguage is the mapping language that matches every target.
const anyLanguage = "any"

// unmappedPrefix names a reason the mapping does not cover, in place of a caveat id.
const unmappedPrefix = "unmapped:"

var caveatPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$`)

// parseCaveats decodes and validates a caveats file. Unknown fields are refused.
func parseCaveats(data []byte) (Caveats, error) {
	var c Caveats
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Caveats{}, fmt.Errorf("caveats: %w", err)
	}
	if err := c.validate(); err != nil {
		return Caveats{}, fmt.Errorf("caveats: %w", err)
	}
	return c, nil
}

func loadCaveats(path string) (Caveats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Caveats{}, err
	}
	return parseCaveats(data)
}

func (c Caveats) validate() error {
	if len(c.Mappings) == 0 {
		return fmt.Errorf("no mappings")
	}
	type key struct {
		reason, language string
		runWide          bool
	}
	seen := map[key]bool{}
	for _, m := range c.Mappings {
		switch {
		case m.Reason == "" || strings.TrimSpace(m.Reason) != m.Reason:
			return fmt.Errorf("mapping for %q: reason %q is empty or padded", m.Caveat, m.Reason)
		case !caveatPattern.MatchString(m.Caveat):
			return fmt.Errorf("%s: caveat %q is not a caveat id (e.g. JAVA-GRAPH-PRECONDITION)", m.Reason, m.Caveat)
		case m.Language != anyLanguage && !knownLanguage(m.Language):
			return fmt.Errorf("%s: language %q is not %s or one of %s", m.Reason, m.Language, anyLanguage, strings.Join(languages, ", "))
		case !strings.HasSuffix(m.DefinedIn, ".go") || strings.HasSuffix(m.DefinedIn, "_test.go"):
			return fmt.Errorf("%s: defined_in %q is not the Go file that declares the reason", m.Reason, m.DefinedIn)
		}
		k := key{m.Reason, m.Language, m.RunWide}
		if seen[k] {
			return fmt.Errorf("%s is mapped twice for language %s (run_wide %v)", m.Reason, m.Language, m.RunWide)
		}
		seen[k] = true
	}
	structural := map[string]bool{}
	for _, s := range c.Structural {
		switch {
		case !caveatPattern.MatchString(s.Caveat):
			return fmt.Errorf("structural caveat %q is not a caveat id", s.Caveat)
		case !knownLanguage(s.Language):
			return fmt.Errorf("structural %s: language %q is not one of %s", s.Caveat, s.Language, strings.Join(languages, ", "))
		case structural[s.Language+"/"+s.Caveat]:
			return fmt.Errorf("structural %s is listed twice for %s", s.Caveat, s.Language)
		}
		structural[s.Language+"/"+s.Caveat] = true
	}
	return nil
}

// caveatFor returns the caveat a reason fires on a target of the given language, or
// unmapped:<reason>. A language's own mapping wins over an "any" mapping, and a run-wide
// occurrence prefers the run-wide mapping.
func (c Caveats) caveatFor(reason, language string, runWide bool) string {
	for _, lang := range []string{language, anyLanguage} {
		for _, wantRunWide := range []bool{true, false} {
			if wantRunWide && !runWide {
				continue
			}
			for _, m := range c.Mappings {
				if m.Reason == reason && m.Language == lang && m.RunWide == wantRunWide {
					return m.Caveat
				}
			}
		}
	}
	return unmappedPrefix + reason
}

// CaveatHit is one caveat that fired on a repository.
type CaveatHit struct {
	// Caveat is the caveat id, or unmapped:<reason> for a reason the mapping does not cover.
	Caveat string `json:"caveat"`
	// Findings counts the findings the caveat affected (see repoCaveats).
	Findings int `json:"findings"`
	// RunWide is true when a reason behind the caveat was declared for the whole run.
	RunWide bool `json:"run_wide"`
	// Reasons are the raw reason codes behind the caveat, sorted.
	Reasons []string `json:"reasons"`
}

// repoCaveats tallies the caveats a report fired on a target of the given language. A reason
// fires wherever the report carries it: a partiality note (run-wide when it names no package and
// no path), a row's undetermined_reason, or a package's partial_reason.
//
// A finding is affected by a reason when it names the reason itself: as its undetermined_reason
// or as its package's partial_reason. A did-not-run partiality note whose reason is no row's
// undetermined_reason is a limit that holds the run's refutations: it affects every row left undetermined with
// analysis_did_not_run. The report does not say which limit held which of those rows, so each
// such caveat counts all of them, an upper bound. An inherent-limit note holds no verdict and
// affects none.
func repoCaveats(c Caveats, language string, r report.Report) []CaveatHit {
	type tally struct {
		findings map[int]bool
		runWide  bool
		reasons  map[string]bool
	}
	hits := map[string]*tally{}
	fire := func(reason string, runWide bool, findings ...int) {
		id := c.caveatFor(reason, language, runWide)
		t := hits[id]
		if t == nil {
			t = &tally{findings: map[int]bool{}, reasons: map[string]bool{}}
			hits[id] = t
		}
		t.runWide = t.runWide || runWide
		t.reasons[reason] = true
		for _, i := range findings {
			t.findings[i] = true
		}
	}

	rowReasons := map[string]bool{}
	var didNotRun []int
	for i, f := range r.Advisories {
		if f.Verdict != report.VerdictUndetermined {
			continue
		}
		rowReasons[f.UndeterminedReason] = true
		if f.UndeterminedReason == report.ReasonAnalysisDidNotRun {
			didNotRun = append(didNotRun, i)
		}
	}
	for i, f := range r.Advisories {
		if f.Verdict == report.VerdictUndetermined {
			fire(f.UndeterminedReason, false, i)
		}
		if f.Package != nil && f.Package.PartialReason != "" {
			fire(f.Package.PartialReason, false, i)
		}
	}
	for _, p := range r.SBOM.Packages {
		if p.PartialReason != "" {
			fire(p.PartialReason, false)
		}
	}
	for _, n := range r.Partiality {
		runWide := n.Package == "" && n.Path == ""
		if n.EffectiveClass() == report.PartialityDidNotRun && !rowReasons[n.Reason] {
			fire(n.Reason, runWide, didNotRun...)
		} else {
			fire(n.Reason, runWide)
		}
	}

	out := make([]CaveatHit, 0, len(hits))
	for id, t := range hits {
		out = append(out, CaveatHit{Caveat: id, Findings: len(t.findings), RunWide: t.runWide, Reasons: sortedSet(t.reasons)})
	}
	sort.Slice(out, func(i, j int) bool { return caveatLess(out[i].Caveat, out[j].Caveat) })
	return out
}

// caveatLess orders caveat ids, unmapped reasons last.
func caveatLess(a, b string) bool {
	ua, ub := strings.HasPrefix(a, unmappedPrefix), strings.HasPrefix(b, unmappedPrefix)
	if ua != ub {
		return ub
	}
	return a < b
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LanguageCaveats is the per-language roll-up: each caveat that fired on the language's targets.
type LanguageCaveats struct {
	Language string         `json:"language"`
	Caveats  []CaveatRollup `json:"caveats"`
}

// CaveatRollup is one caveat across a language's targets.
type CaveatRollup struct {
	Caveat string `json:"caveat"`
	// Repos is how many of the language's targets the caveat fired on; for a caveat that always
	// applies, every target of the language.
	Repos int `json:"repos"`
	// FiredOn names those targets, in target order. Empty for a caveat that always applies.
	FiredOn []string `json:"fired_on,omitempty"`
	// Findings sums CaveatHit.Findings over FiredOn.
	Findings      int  `json:"findings"`
	AlwaysApplies bool `json:"always_applies,omitempty"`
}

// addCaveats fills each repository's caveats and the per-language roll-up. Only a repository
// with a readable report gets caveats; it changes no pass, failure or alert. mappingErr is why
// the mapping could not be read, if it could not: every reason then shows unmapped.
func (s *Summary) addCaveats(c Caveats, mappingErr error, results map[string]*scanResult) {
	if mappingErr != nil {
		s.CaveatMappingError = mappingErr.Error()
	}
	byLang := map[string]map[string]*CaveatRollup{}
	targets := map[string]int{}
	for i := range s.Repos {
		res := &s.Repos[i]
		targets[res.Language]++
		sr := results[res.Repo]
		if sr == nil || !sr.hasReport {
			continue
		}
		r, err := decodeReport(sr.report)
		if err != nil {
			continue
		}
		res.Caveats = repoCaveats(c, res.Language, r)
		if byLang[res.Language] == nil {
			byLang[res.Language] = map[string]*CaveatRollup{}
		}
		for _, h := range res.Caveats {
			ru := byLang[res.Language][h.Caveat]
			if ru == nil {
				ru = &CaveatRollup{Caveat: h.Caveat}
				byLang[res.Language][h.Caveat] = ru
			}
			ru.Repos++
			ru.FiredOn = append(ru.FiredOn, repoName(res.Repo))
			ru.Findings += h.Findings
		}
	}
	for _, sc := range c.Structural {
		if targets[sc.Language] == 0 {
			continue
		}
		if byLang[sc.Language] == nil {
			byLang[sc.Language] = map[string]*CaveatRollup{}
		}
		byLang[sc.Language][sc.Caveat] = &CaveatRollup{Caveat: sc.Caveat, Repos: targets[sc.Language], AlwaysApplies: true}
	}
	s.Caveats = []LanguageCaveats{}
	for _, l := range languages {
		if targets[l] == 0 {
			continue
		}
		lc := LanguageCaveats{Language: l, Caveats: []CaveatRollup{}}
		for _, ru := range byLang[l] {
			lc.Caveats = append(lc.Caveats, *ru)
		}
		sort.Slice(lc.Caveats, func(i, j int) bool { return caveatLess(lc.Caveats[i].Caveat, lc.Caveats[j].Caveat) })
		s.Caveats = append(s.Caveats, lc)
	}
}

// caveatMarkdown renders the job summary's caveat section: one table per language with targets.
func (s Summary) caveatMarkdown() string {
	if s.Caveats == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n### Caveats by language\n\n")
	b.WriteString("Capability-matrix caveats each repo's report fired, from `floor/caveats.json`. Informational: they never fail the run. A reason with no mapping is shown as `unmapped:<reason>`.\n")
	if s.CaveatMappingError != "" {
		fmt.Fprintf(&b, "\n**The caveat mapping could not be read** (%s), so every reason is shown unmapped.\n", cell(s.CaveatMappingError))
	}
	for _, lc := range s.Caveats {
		fmt.Fprintf(&b, "\n#### %s\n\n", lc.Language)
		if len(lc.Caveats) == 0 {
			b.WriteString("No caveat fired.\n")
			continue
		}
		b.WriteString("| Caveat | Repos fired on | Findings affected |\n|---|---|---|\n")
		for _, ru := range lc.Caveats {
			if ru.AlwaysApplies {
				fmt.Fprintf(&b, "| `%s` | always applies | — |\n", cell(ru.Caveat))
				continue
			}
			fmt.Fprintf(&b, "| `%s` | %d (%s) | %d |\n", cell(ru.Caveat), ru.Repos, cell(strings.Join(ru.FiredOn, ", ")), ru.Findings)
		}
	}
	return b.String()
}
