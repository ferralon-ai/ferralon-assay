// Package vulnclass recognizes a vulnerability class from an advisory's CWE + summary.
//
// Recognition is ADVISORY ONLY — it shapes the model's framing and selects the proof route, but
// NEVER decides a verdict and NEVER touches the proven gate (inv.5). A class that is recognized but
// cannot be soundly routed is surfaced as an honest partiality, never as "clear" (ROADMAP §scope
// honesty). The pure CWE→class recognizer is the free/OSS half of the former proof.vulnclass; the
// proprietary class→proof-route table stays Service-side.
package vulnclass

import "strings"

// Class is the vulnerability class recognized from an advisory's CWE + summary. It is an OPEN
// string (like proof.Strategy): the recognized classes have constants, but an unrecognized advisory
// yields ClassUnknown rather than a wrong guess.
type Class string

const (
	// ClassUnknown is the honest default: the advisory's class could not be recognized, so the
	// pipeline records "not assessed" for class-specific routing rather than guessing. It is NEVER
	// "clear" — an unrecognized class falls back to the generic direct-derivation route.
	ClassUnknown Class = ""

	// --- Phase-1 classes (already reachable end-to-end; recognized here for completeness) ---

	// ClassMemorySafety is an out-of-bounds read/write or panic-on-malformed-input class
	// (e.g. GO-2021-0113).
	ClassMemorySafety Class = "memory_safety"
	// ClassInjection is a command, SQL, or code injection class.
	ClassInjection Class = "injection"
	// ClassPathTraversal is a "../" escape or zip-slip class.
	ClassPathTraversal Class = "path_traversal"
	// ClassDeserialize is an unsafe-deserialization class.
	ClassDeserialize Class = "deserialization"

	// --- Phase-2 W5 expansion classes ---

	// ClassSSRF is a server-side request forgery class (CWE-918).
	ClassSSRF Class = "ssrf"
	// ClassAuthBypass is an authentication/authorization bypass class (CWE-287/CWE-862/CWE-863).
	ClassAuthBypass Class = "auth_bypass"
	// ClassDoS is a resource-exhaustion / uncontrolled-consumption class (CWE-400/CWE-770).
	ClassDoS Class = "dos"
	// ClassTemplateInj is a server-side template injection class (CWE-1336/CWE-94).
	ClassTemplateInj Class = "template_injection"
	// ClassUnsafeRefl is an unsafe-reflection / type-confusion class (CWE-470).
	ClassUnsafeRefl Class = "unsafe_reflection"

	// --- U4 vulnclass adds ---
	// ClassOpenRedirect is recognized AND routable: its reachability mechanism (attacker-controlled
	// URL reaching a redirect sink) mirrors SSRF, so it gets a real Service-side route.
	ClassOpenRedirect Class = "open_redirect" // unvalidated redirect (CWE-601)
	// ClassPrototypePollution is recognized but has NO proof route this cycle: its sound proof
	// (computed-member taint) is deferred to a later slice. It classifies advisories so framing is
	// honest, but RouteForClass returns no route — the pipeline falls to the conservative default and
	// stays Undetermined (fail-open, never a fabricated verdict).
	ClassPrototypePollution Class = "prototype_pollution" // prototype pollution (CWE-1321)
)

// KnownClasses returns the recognized class constants (ClassUnknown excluded), for documentation
// and the completeness guard. It is NOT a closed gate: ClassifyAdvisory may still return
// ClassUnknown for an advisory none of these match.
func KnownClasses() []Class {
	return []Class{
		ClassMemorySafety, ClassInjection, ClassPathTraversal, ClassDeserialize,
		ClassSSRF, ClassAuthBypass, ClassDoS, ClassTemplateInj, ClassUnsafeRefl,
		ClassOpenRedirect, ClassPrototypePollution,
	}
}

// AdvisoryClass carries the inputs class recognition reads from a normalized advisory. CWEs are the
// strongest signal (structured, source-attributed); the summary is a weaker keyword fallback. Both
// are advisory facts the model already sees — recognition adds NO new trust surface (inv.5).
type AdvisoryClass struct {
	CWEs    []string // e.g. ["CWE-918"]; case-insensitive, "CWE-" prefix optional
	Summary string   // free-text advisory summary (keyword fallback only)
}

// cweClass maps a normalized CWE id (upper-case, "CWE-" prefix) to its class. CWE is authoritative:
// when an advisory carries a CWE we recognize, the summary keywords are not consulted.
var cweClass = map[string]Class{
	"CWE-918":  ClassSSRF,
	"CWE-287":  ClassAuthBypass,
	"CWE-285":  ClassAuthBypass, // Improper Authorization
	"CWE-862":  ClassAuthBypass,
	"CWE-863":  ClassAuthBypass,
	"CWE-306":  ClassAuthBypass,
	"CWE-400":  ClassDoS,
	"CWE-770":  ClassDoS,
	"CWE-1333": ClassDoS, // ReDoS
	"CWE-1336": ClassTemplateInj,
	"CWE-94":   ClassTemplateInj,
	"CWE-470":  ClassUnsafeRefl,
	"CWE-787":  ClassMemorySafety,
	"CWE-125":  ClassMemorySafety,
	"CWE-77":   ClassInjection, // generic command injection (parent of CWE-78)
	"CWE-78":   ClassInjection,
	"CWE-89":   ClassInjection,
	"CWE-22":   ClassPathTraversal,
	"CWE-502":  ClassDeserialize,
	"CWE-601":  ClassOpenRedirect,
	"CWE-1321": ClassPrototypePollution,
}

// summaryKeywords maps a lower-case keyword phrase to a class, consulted ONLY when no recognized
// CWE is present. Ordering matters: the slice is scanned in order so a more specific phrase wins
// over a generic one (e.g. "server-side request forgery" before "request").
var summaryKeywords = []struct {
	phrase string
	class  Class
}{
	{"server-side request forgery", ClassSSRF},
	{"ssrf", ClassSSRF},
	{"server-side template injection", ClassTemplateInj},
	{"template injection", ClassTemplateInj},
	{"authentication bypass", ClassAuthBypass},
	{"authorization bypass", ClassAuthBypass},
	{"auth bypass", ClassAuthBypass},
	{"access control", ClassAuthBypass},
	{"denial of service", ClassDoS},
	{"resource exhaustion", ClassDoS},
	{"uncontrolled resource consumption", ClassDoS},
	{"unbounded", ClassDoS},
	{"regular expression denial", ClassDoS},
	{"unsafe reflection", ClassUnsafeRefl},
	{"command injection", ClassInjection},
	{"sql injection", ClassInjection},
	{"code injection", ClassInjection},
	{"path traversal", ClassPathTraversal},
	{"directory traversal", ClassPathTraversal},
	{"zip slip", ClassPathTraversal},
	{"deserialization", ClassDeserialize},
	{"open redirect", ClassOpenRedirect},
	{"prototype pollution", ClassPrototypePollution},
	{"out-of-bounds", ClassMemorySafety},
	{"out of bounds", ClassMemorySafety},
	{"buffer overflow", ClassMemorySafety},
	{"panic", ClassMemorySafety},
}

// ClassifyAdvisory recognizes the vulnerability class from advisory facts. CWE is authoritative
// when present and recognized; otherwise a keyword scan of the summary is the fallback. An advisory
// that matches neither yields ClassUnknown — the honest "not assessed for class" outcome, never a
// guess. This function is PURE and advisory-only: it never reads codebase facts, never emits proof,
// and its output is consumed only to shape framing and select a route (inv.5).
func ClassifyAdvisory(adv AdvisoryClass) Class {
	for _, raw := range adv.CWEs {
		if c, ok := cweClass[normalizeCWE(raw)]; ok {
			return c
		}
	}
	s := strings.ToLower(adv.Summary)
	for _, kw := range summaryKeywords {
		if strings.Contains(s, kw.phrase) {
			return kw.class
		}
	}
	return ClassUnknown
}

// ClassFromCWE resolves a single CWE id (any of the normalizeCWE-accepted forms) to its
// recognized class, exposing the same authoritative cweClass table ClassifyAdvisory consults. It
// exists for callers (e.g. pipeline's sink_kind "code_execution" fan-out) that need to reason about
// one CWE at a time rather than the whole-advisory CWE-then-keyword precedence ClassifyAdvisory
// applies. An unrecognized CWE returns ok=false — never a guessed class.
func ClassFromCWE(raw string) (Class, bool) {
	c, ok := cweClass[normalizeCWE(raw)]
	return c, ok
}

// normalizeCWE upper-cases and ensures the "CWE-" prefix on a raw CWE id ("918", "cwe-918",
// "CWE-918" all normalize to "CWE-918"). A non-numeric token normalizes to itself (no match).
func normalizeCWE(raw string) string {
	t := strings.ToUpper(strings.TrimSpace(raw))
	if t == "" {
		return ""
	}
	if !strings.HasPrefix(t, "CWE-") {
		t = "CWE-" + strings.TrimPrefix(t, "CWE")
	}
	return t
}
