package javaanalysis

import (
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// AOP-proxy sink overlay (#2, edge-seam.md §3). Spring realizes @Async/@Scheduled,
// @Transactional/@Cacheable, and @Aspect advice by wrapping the target bean in a
// generated proxy: the call the source lexically makes is not the call that runs. Two
// consequences weaken a value-flow claim through such a sink, so this overlay ADDS
// partiality (never removes a reason, never flips to NotExploitable — inv.5):
//
//   - @Async on the method or its enclosing class, or @Scheduled on the method, severs
//     the synchronous-call assumption (control-flow discontinuity) → async_boundary.
//   - @Transactional / @Cacheable on the method or class, an enclosing @Aspect, or an
//     @Around/@Before/@After advice method means the real target is a generated proxy
//     with an interceptor this analysis does not read → proxy_mediated.
//
// Both may hold; their reasons union. Annotations are matched by SIMPLE name
// (namespace-agnostic, the lane convention), so org.springframework.* and the
// javax↔jakarta @Transactional split all resolve.
//
// KNOWN RESIDUE (declared, not papered over — inv.5):
//   - Sink-node advice ONLY. Advice sitting on an INTERMEDIATE node of the ingress→sink
//     path is not modeled here. This is a WEAKENING-only omission: a missed proxy can
//     only fail to add partiality, never fabricate reachability, so it stays sound.
//   - First-party (prog.sourceClasses) ONLY. Advice declared in a dependency classfile
//     is invisible by design (*program carries no dep classfile classes) — honest residue.
func init() {
	registerSinkClassifier(newAOPClassifier)
}

// Simple-name marker sets. Matching is namespace-agnostic (simple name only), the lane
// convention, so both javax and jakarta @Transactional and every org.springframework.*
// stereotype resolve without an import table.
var (
	asyncMethodMarkers = map[string]bool{"Async": true, "Scheduled": true}
	asyncClassMarkers  = map[string]bool{"Async": true}
	proxyMethodMarkers = map[string]bool{"Transactional": true, "Cacheable": true, "Around": true, "Before": true, "After": true}
	proxyClassMarkers  = map[string]bool{"Transactional": true, "Cacheable": true, "Aspect": true}
)

// newAOPClassifier materializes the AOP classifier against one analysis program: it
// precomputes, once, the reasons every first-party sink method warrants from the advice
// on that method and its enclosing class, then returns a per-sink lookup closure. Empty
// map ⇒ the closure returns nil for every sink (byte-identical to no overlay).
func newAOPClassifier(prog *program) func(symbolID string) []string {
	byID := make(map[string][]string)
	for _, sc := range prog.sourceClasses {
		classAsync := hasAnyMarker(sc.classAnnos, asyncClassMarkers)
		classProxy := hasAnyMarker(sc.classAnnos, proxyClassMarkers)
		for _, m := range sc.methods {
			async := classAsync || hasAnyMarker(m.annos, asyncMethodMarkers)
			proxy := classProxy || hasAnyMarker(m.annos, proxyMethodMarkers)
			if !async && !proxy {
				continue
			}
			var reasons []string
			if async {
				reasons = append(reasons, plugin.PartialReasonAsyncBoundary)
			}
			if proxy {
				reasons = append(reasons, plugin.PartialReasonProxyMediated)
			}
			sort.Strings(reasons) // stable emission order (determinism)
			byID[methodSCIP(sc.pkg, sc.enclosing, m.name, m.arity)] = reasons
		}
	}
	return func(symbolID string) []string {
		return byID[symbolID]
	}
}

// hasAnyMarker reports whether any annotation in annos matches a simple name in markers.
func hasAnyMarker(annos []parsedAnno, markers map[string]bool) bool {
	for _, a := range annos {
		if markers[a.name] {
			return true
		}
	}
	return false
}
