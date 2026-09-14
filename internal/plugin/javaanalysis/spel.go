package javaanalysis

import (
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// SpEL presence overlay (#4, edge-seam.md §3). A Spring Expression Language template
// embedded in an annotation string — the SpEL form #{…} or the property placeholder
// ${…} — sits at or guarding a first-party sink whenever the sink method's own
// annotations, or its enclosing class's annotations, carry such a string. Examples:
// @Value("#{systemProperties['rate']}"), @Query("… #{…}"), @PreAuthorize("… #{…}"),
// @Cacheable(key="#{…}"). The expression is interpreted by the Spring runtime, not by
// this analyzer, so its value-flow is un-reasoned: a sink so marked MUST NOT be
// rendered as cleanly analyzed. The overlay emits plugin.PartialReasonSpELPresent
// (spel_present) for it.
//
// Honest limitations (inv.5 — this overlay only ADDS partiality, it never fabricates
// reachability and never retires a reason):
//
//   - Presence, never content. We flag THAT a SpEL/placeholder template is present at
//     the sink, not what it evaluates to or whether it is exploitable (edge-seam.md §2).
//   - First-party source only. This works because the source lexer recovers the string
//     values of first-party Java annotations (Phase-1a/1d, spring-surface.md §0). SpEL
//     living in a dependency-resident annotation is not visible to the source scan and
//     is not flagged here.
//   - First string element only. The retained parsedAnno.value is the FIRST recovered
//     string element of each annotation, so a template in a non-first element — e.g.
//     @Cacheable(cacheNames="x", key="#{…}") — is not seen. That residue is honest: an
//     un-flagged sink is never asserted clean, it is simply not marked by THIS overlay.
const spelMarkerSpEL = "#{"

// spelMarkerPlaceholder is the Spring property-placeholder form (${…}), scanned
// alongside #{…}; either marker in an annotation string value flags the sink.
const spelMarkerPlaceholder = "${"

func init() {
	registerSinkClassifier(newSpELClassifier)
}

// newSpELClassifier is the H3 factory: given the active program it precomputes the set
// of first-party sink ids whose own or enclosing-class annotation string values contain
// a SpEL/placeholder template, then returns a per-sink classifier that emits
// spel_present for exactly those ids. Precomputed once per analysis (not per sink).
func newSpELClassifier(prog *program) func(symbolID string) []string {
	spelSinks := map[string]bool{}
	for _, sc := range prog.sourceClasses {
		classHasSpEL := annosHaveSpEL(sc.classAnnos)
		for _, m := range sc.methods {
			if classHasSpEL || annosHaveSpEL(m.annos) {
				spelSinks[methodSCIP(sc.pkg, sc.enclosing, m.name, m.arity)] = true
			}
		}
	}
	return func(symbolID string) []string {
		if spelSinks[symbolID] {
			return []string{plugin.PartialReasonSpELPresent}
		}
		return nil
	}
}

// annosHaveSpEL reports whether any annotation's recovered first string element value
// contains a SpEL template (#{…}) or a property placeholder (${…}).
func annosHaveSpEL(annos []parsedAnno) bool {
	for _, a := range annos {
		if strings.Contains(a.value, spelMarkerSpEL) || strings.Contains(a.value, spelMarkerPlaceholder) {
			return true
		}
	}
	return false
}
