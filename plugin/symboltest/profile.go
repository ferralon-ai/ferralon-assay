package symboltest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// KnownGap declares an expected producer gap for a ProfileRow: the construct
// EXISTS in the language but the producer does not emit its canonical symbol YET,
// and a PLAN will close it (xfail). It supersedes t.Skip, which would silently
// hide the gap — a KnownGap names the gap loudly and points at the closing PLAN.
// Booking a KnownGap is a test-side declaration, never a change to a producer.
//
// Distinguish sharply from NotApplicable: KnownGap = "construct exists, unemitted
// yet, PLAN closes it"; NotApplicable = "construct does not exist in this
// language, ever." Never use a KnownGap to duck a genuinely-absent construct — a
// Closes that will never come is the fake-a-gap anti-pattern the fleet honesty bar
// forbids (§3.5).
type KnownGap struct {
	Reason string // why the producer cannot match Want yet
	Closes string // the PLAN id that will close it, e.g. "PLAN-300"
}

// NotApplicable declares that a required category has NO construct in this
// language (Go has no language-level constructor; Java has no free functions; JS
// has no method overloading). An NA row asserts nothing about producer output —
// there is no canonical symbol for a nonexistent construct — yet it SATISFIES the
// eight-category coverage guard: the category is considered and explicitly
// declared inapplicable, not silently dropped. The honesty lives in Reason being a
// truthful human-review claim (you cannot mechanically prove a language lacks a
// construct); it declares absence, it never asserts a behavior the harness cannot
// produce (§3.5).
type NotApplicable struct {
	Reason string // why this category has no construct in this language
}

// ProfileRow binds one declaration category to a concrete source construct and to
// the canonical plugin.Symbol a conformant producer must emit. A row is in exactly
// ONE of three states:
//
//   - must-match   (Gap == nil && NA == nil): producer output MUST equal Want.
//   - known-gap    (Gap != nil):              expected gap, xfail (§3).
//   - not-applicable (NA != nil):             honest absence, asserts nothing (§3.5).
//
// Setting both Gap and NA is an author error; Evaluate reports it as a failure.
type ProfileRow struct {
	Category  string         // one of RequiredCategories (verbatim label)
	Construct string         // human description of the source construct
	Want      plugin.Symbol  // the expected CANONICAL symbol (structured fields populated)
	Gap       *KnownGap      // non-nil = documented expected gap (construct exists, unemitted yet)
	NA        *NotApplicable // non-nil = construct does not exist in this language
}

// Profile is a language's canonical symbol profile: ordered rows, each per §1.
type Profile struct {
	Language string
	Rows     []ProfileRow
}

// RequiredCategories is the canonical, frozen eight-label set every conformant
// profile must cover, verbatim from TestSymbolCategories (plugin/contract_test.go:70-77).
// The eight are an axis product over Kind + Enclosing + Descriptor + Generated,
// not eight SymbolKinds.
var RequiredCategories = []string{
	"packages/modules",
	"types",
	"functions",
	"methods",
	"constructors",
	"overloads/generics",
	"nested declarations",
	"generated symbols",
}

// FindingKind classifies an evaluate result. Regression / SilentClosure /
// MissingCategory are failures (AssertProfile t.Error's them); CollapsedSCIP is a
// diagnostic note (AssertProfile t.Logf's it, never fails equality on it).
type FindingKind int

const (
	// FindingRegression: a must-match row (Gap == nil) had no structurally-equal emitted symbol.
	FindingRegression FindingKind = iota
	// FindingSilentClosure: a known-gap row (Gap != nil) unexpectedly matched — the gap closed silently.
	FindingSilentClosure
	// FindingMissingCategory: the profile does not cover a required category.
	FindingMissingCategory
	// FindingRowStateConflict: a row sets both Gap and NA (author error — a row is in exactly one state).
	FindingRowStateConflict
	// FindingCollapsedSCIP: diagnostic — a matched emitted symbol has SCIP == DisplayName (no distinct wire id).
	FindingCollapsedSCIP
)

// Finding is one result of evaluating a Profile against emitted symbols.
type Finding struct {
	Kind      FindingKind
	Category  string
	Construct string
	Message   string
}

// IsFailure reports whether the finding should fail the test (vs. a diagnostic note).
func (f Finding) IsFailure() bool { return f.Kind != FindingCollapsedSCIP }

// IdentityKey projects a Symbol onto its structured-identity equality key by
// zeroing the diagnostic-only SCIP and DisplayName fields (§2). Two Symbols share
// a canonical identity iff their IdentityKey values are == — a plain comparable
// struct compare, no go-cmp and no reflect.
func IdentityKey(s plugin.Symbol) plugin.Symbol {
	s.SCIP = ""
	s.DisplayName = ""
	return s
}

// AssertProfile runs p against a producer's emitted symbols and applies §2/§3
// semantics. It matches each Want by the structured-identity key, applies KnownGap
// xfail, t.Error's on regression / silent-closure with a hand-rolled field diff,
// and t.Logf's the SCIP==DisplayName diagnostic. It also fails a profile that
// drops any required category.
func AssertProfile(t *testing.T, p Profile, emitted []plugin.Symbol) {
	t.Helper()
	for _, f := range Evaluate(p, emitted) {
		if f.IsFailure() {
			t.Errorf("%s", f.Message)
		} else {
			t.Logf("diagnostic: %s", f.Message)
		}
	}
}

// Evaluate is the pure decision core: it returns every Finding for p against
// emitted, without touching testing.T. AssertProfile wraps it and maps failures to
// t.Error / diagnostics to t.Logf; a consumer that needs to assert on the results
// itself (e.g. a lane counting findings by Kind) calls Evaluate directly.
func Evaluate(p Profile, emitted []plugin.Symbol) []Finding {
	var findings []Finding

	// Coverage guard: a profile that silently drops a required category is a defect.
	present := make(map[string]bool, len(p.Rows))
	for _, r := range p.Rows {
		present[r.Category] = true
	}
	for _, c := range RequiredCategories {
		if !present[c] {
			findings = append(findings, Finding{
				Kind:     FindingMissingCategory,
				Category: c,
				Message:  fmt.Sprintf("profile %q drops required category %q (§1 requires all eight)", p.Language, c),
			})
		}
	}

	// Index emitted symbols by their identity key (first wins) for O(1) matching.
	byKey := make(map[plugin.Symbol]plugin.Symbol, len(emitted))
	for _, e := range emitted {
		k := IdentityKey(e)
		if _, ok := byKey[k]; !ok {
			byKey[k] = e
		}
	}

	for _, r := range p.Rows {
		// A row must be in exactly one of three states (§3.5). Both set = author error.
		if r.Gap != nil && r.NA != nil {
			findings = append(findings, Finding{
				Kind:      FindingRowStateConflict,
				Category:  r.Category,
				Construct: r.Construct,
				Message: fmt.Sprintf("row %q (%s) sets both KnownGap and NotApplicable: a row is in exactly one state (must-match / known-gap / not-applicable)",
					r.Category, r.Construct),
			})
			continue
		}
		// Not-applicable: the construct does not exist in this language. Asserts
		// nothing about emitted; it has already satisfied the coverage guard above.
		if r.NA != nil {
			continue
		}

		wantKey := IdentityKey(r.Want)
		matched, ok := byKey[wantKey]

		switch {
		case r.Gap == nil && !ok:
			// must-match, but nothing emitted matches → regression.
			findings = append(findings, Finding{
				Kind:      FindingRegression,
				Category:  r.Category,
				Construct: r.Construct,
				Message: fmt.Sprintf("regression: must-match row %q (%s) has no emitted symbol with canonical identity %s\n%s",
					r.Category, r.Construct, renderKey(wantKey), diff(r.Want, nearest(r.Want, emitted))),
			})
		case r.Gap != nil && ok:
			// expected-failure, but a match unexpectedly exists → gap silently closed.
			findings = append(findings, Finding{
				Kind:      FindingSilentClosure,
				Category:  r.Category,
				Construct: r.Construct,
				Message: fmt.Sprintf("known gap %q silently closed (Closes=%s): promote the row by deleting its KnownGap\n%s",
					r.Category, r.Gap.Closes, diff(r.Want, matched)),
			})
		}

		// Diagnostic (never an equality failure): a matched symbol with no distinct
		// wire id (SCIP == DisplayName, the sym() collapse) is producer-health noise.
		if ok && matched.SCIP == matched.DisplayName {
			findings = append(findings, Finding{
				Kind:      FindingCollapsedSCIP,
				Category:  r.Category,
				Construct: r.Construct,
				Message: fmt.Sprintf("no distinct SCIP wire id emitted for %q (%s): SCIP==DisplayName==%q",
					r.Category, r.Construct, matched.SCIP),
			})
		}
	}
	return findings
}

// renderKey renders an identity key compactly for a failure message.
func renderKey(k plugin.Symbol) string {
	return fmt.Sprintf("{Kind:%q Package:%q Enclosing:%q Name:%q Descriptor:%q Generated:%t}",
		k.Kind, k.Package, k.Enclosing, k.Name, k.Descriptor, k.Generated)
}

// nearest picks the emitted symbol most likely to be the one a Want row intended,
// scoring by shared Name / Package / DisplayName-leaf, so diff shows a useful
// delta rather than a zero value. Returns the zero Symbol when emitted is empty.
func nearest(want plugin.Symbol, emitted []plugin.Symbol) plugin.Symbol {
	var best plugin.Symbol
	bestScore := -1
	for _, e := range emitted {
		score := 0
		if want.Name != "" && (e.Name == want.Name ||
			e.DisplayName == want.Name ||
			strings.HasSuffix(e.DisplayName, "."+want.Name) ||
			strings.HasSuffix(e.DisplayName, ")."+want.Name)) {
			score += 2
		}
		if want.Package != "" && e.Package == want.Package {
			score++
		}
		if score > bestScore {
			bestScore = score
			best = e
		}
	}
	return best
}

// diff renders a hand-rolled per-field delta of the identity fields (want vs the
// nearest emitted symbol), marking the fields that differ. SCIP/DisplayName are
// shown for context but flagged as excluded from equality.
func diff(want, got plugin.Symbol) string {
	var b strings.Builder
	b.WriteString("  identity diff (want vs nearest emitted; * = differs):\n")
	line := func(field, w, g string) {
		mark := " "
		if w != g {
			mark = "*"
		}
		fmt.Fprintf(&b, "    %s %-11s want=%q got=%q\n", mark, field, w, g)
	}
	line("Kind", string(want.Kind), string(got.Kind))
	line("Package", want.Package, got.Package)
	line("Enclosing", want.Enclosing, got.Enclosing)
	line("Name", want.Name, got.Name)
	line("Descriptor", want.Descriptor, got.Descriptor)
	line("Generated", fmt.Sprintf("%t", want.Generated), fmt.Sprintf("%t", got.Generated))
	fmt.Fprintf(&b, "      (excluded from equality) want.SCIP=%q got.SCIP=%q got.DisplayName=%q\n",
		want.SCIP, got.SCIP, got.DisplayName)
	return b.String()
}
