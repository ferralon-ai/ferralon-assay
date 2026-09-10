package javaanalysis

import "github.com/ferralon-ai/ferralon-assay/plugin"

// #5 filter/security guard overlay (edge-seam.md §5, spring-surface.md §4).
//
// A first-party sink whose declaring method or class carries a Spring Security
// authorization annotation (@PreAuthorize/@PostAuthorize/@Secured/@RolesAllowed),
// or whose declaring type is a servlet Filter / Spring HandlerInterceptor /
// OncePerRequestFilter, sits behind a security control we can SEE but cannot
// EVALUATE: we cannot prove the control sanitizes the taint or blocks the caller.
// The honest verdict is the tri-state UNKNOWN arm — guard_unknown — NOT a positive
// "guarded"/"safe" signal.
//
// inv.5 (cardinal): this overlay only ADDS partiality. It never removes a
// reachability / no_known_ingress reason and never flips a sink to NotExploitable.
// A guard whose effect is undeterminable must never downgrade exploitability.
//
// Honest boundary (DECLARED ceiling): the positive "guarded" signal is
// unachievable at Assess — we can register that a control exists, never that it
// holds. First-party source only; a guard on a dependency's (bytecode-only) path
// is out of scope here.

// guardAuthzAnnos is the simple-name set of authorization annotations that mark a
// sink as guarded-by-an-unevaluable-control. @RolesAllowed spans the javax↔jakarta
// migration but keeps the same simple name, so a simple-name match covers both.
var guardAuthzAnnos = map[string]bool{
	"PreAuthorize":  true,
	"PostAuthorize": true,
	"Secured":       true,
	"RolesAllowed":  true,
}

// guardFilterSupers is the simple-name set of security-relevant supertypes: a type
// that implements servlet Filter or Spring HandlerInterceptor, or extends
// OncePerRequestFilter, sits on a request path whose filter/interceptor effect we
// cannot evaluate.
var guardFilterSupers = map[string]bool{
	"Filter":               true,
	"HandlerInterceptor":   true,
	"OncePerRequestFilter": true,
}

func init() {
	registerSinkClassifier(newGuardClassifier)
}

// newGuardClassifier materializes the #5 classifier against one analysis program:
// it precomputes the set of first-party sink SCIP ids that carry an unevaluable
// security control (authorization annotation on the method or its enclosing class,
// or a filter/interceptor supertype on the enclosing class), then classifies each
// requested sink by set membership. Precomputing once (not per sink) keeps the
// per-sink classify O(1) and deterministic.
func newGuardClassifier(prog *program) func(symbolID string) []string {
	guarded := map[string]bool{}
	if prog != nil {
		for _, sc := range prog.sourceClasses {
			classGuarded := classHasAuthzAnno(sc) || classIsFilterType(sc)
			for _, m := range sc.methods {
				if !classGuarded && !methodHasAuthzAnno(m) {
					continue
				}
				id := methodSCIP(sc.pkg, sc.enclosing, m.name, m.arity)
				if id != "" {
					guarded[id] = true
				}
			}
		}
	}
	return func(symbolID string) []string {
		if symbolID != "" && guarded[symbolID] {
			// UNKNOWN arm only — additive partiality, never a reachability removal.
			return []string{plugin.PartialReasonGuardUnknown}
		}
		return nil
	}
}

// classHasAuthzAnno reports whether the enclosing class carries a class-level
// authorization annotation (guarding every method it declares).
func classHasAuthzAnno(sc sourceClass) bool {
	for _, a := range sc.classAnnos {
		if guardAuthzAnnos[a.name] {
			return true
		}
	}
	return false
}

// methodHasAuthzAnno reports whether a single method carries an authorization
// annotation directly.
func methodHasAuthzAnno(m sourceMethod) bool {
	for _, a := range m.annos {
		if guardAuthzAnnos[a.name] {
			return true
		}
	}
	return false
}

// classIsFilterType reports whether the class's direct supertypes mark it as a
// servlet filter / Spring interceptor whose effect we cannot evaluate.
func classIsFilterType(sc sourceClass) bool {
	for _, s := range sc.supers {
		if guardFilterSupers[s] {
			return true
		}
	}
	return false
}
