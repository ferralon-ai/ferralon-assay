package javaanalysis

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// FindIngresses identifies framework-idiomatic entry points in the Java module at
// req.BuildDir: methods carrying an HTTP route annotation (@RequestMapping /
// @GetMapping / @PostMapping / @Path / @GET / @POST and siblings), and the
// doGet/doPost/service overrides of a class that extends HttpServlet. Each ingress
// symbol is the method's SCIP id — the SAME id the call graph and symbol resolver
// emit for that method, so the pipeline's firstPartyReachPaths BFS can connect an
// ingress to a reachable sink. An unrecognized method is simply not an ingress
// (absence is declared at the reachability layer, never fabricated here). A
// missing build dir is a hard error (inv.4).
func FindIngresses(ctx context.Context, req plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.IngressResult{}, err
	}

	seen := map[string]bool{}
	var ingresses []plugin.Ingress
	for _, f := range prog.files {
		for _, in := range f.ingresses {
			sym := methodSCIP(f.pkg, in.enclosing, in.name, in.arity)
			key := in.kind + "\x00" + sym + "\x00" + in.selector
			if seen[key] {
				continue
			}
			seen[key] = true
			ingresses = append(ingresses, plugin.Ingress{
				Kind:     in.kind,
				Symbol:   sym,
				Selector: in.selector,
			})
		}
	}

	// Prove-path enrichment (gated by TEGRON_JAVA_ANALYZER_IMAGE). Merge the
	// container-resolved @RestController/@GetMapping routes — DI-wired ingresses
	// the lexical scanner can also see annotationally, but the semantic pass
	// confirms them in the resolved id space the merged call graph uses. On a
	// gated-but-failed run, keep the lexical ingresses and declare
	// Partial(tool_failure). Env unset ⇒ lexical only (byte-identical Assess).
	resolved, gated, ok := scipJavaResolve(ctx, req.BuildDir)
	if gated && ok {
		// Relabel the resolved ingresses into the pure-Go true-arity id space (see
		// reconcileResolvedArity in callgraph.go) so a resolved @GetMapping route
		// symbol is id-equal to the lexical ingress and the merged call graph node.
		resolved = reconcileResolvedArity(prog, resolved)
		ingresses = mergeIngresses(ingresses, resolved.ingresses)
	}

	sort.Slice(ingresses, func(i, j int) bool {
		if ingresses[i].Kind != ingresses[j].Kind {
			return ingresses[i].Kind < ingresses[j].Kind
		}
		if ingresses[i].Symbol != ingresses[j].Symbol {
			return ingresses[i].Symbol < ingresses[j].Symbol
		}
		return ingresses[i].Selector < ingresses[j].Selector
	})

	part := ingressPartiality(prog)
	if gated && !ok {
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}
	return plugin.IngressResult{Partiality: part, Ingresses: ingresses}, nil
}

// mergeIngresses unions the lexical and container-resolved ingress sets,
// deduplicating on (kind, symbol, selector).
func mergeIngresses(lexical, resolved []plugin.Ingress) []plugin.Ingress {
	seen := map[string]bool{}
	key := func(in plugin.Ingress) string { return in.Kind + "\x00" + in.Symbol + "\x00" + in.Selector }
	out := make([]plugin.Ingress, 0, len(lexical)+len(resolved))
	for _, in := range append(append([]plugin.Ingress{}, lexical...), resolved...) {
		k := key(in)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, in)
	}
	return out
}

// ingressPartiality declares completeness of ingress discovery. The lexical
// scanner cannot see DI-wired Spring controllers without an annotation, or
// container-registered servlets, so a skipped construct degrades partiality; a
// clean parse is Complete (the ingresses found ARE complete for the idioms the
// scanner models).
func ingressPartiality(prog *program) plugin.Partiality {
	var reasons []string
	if prog.readFailed {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if prog.skipped {
		reasons = append(reasons, plugin.PartialReasonUnsupported)
	}
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(reasons...)
}

// ResolveDependencySymbols maps the advisory's vulnerable symbol(s) to concrete
// declared Java symbols in the build dir. The advisory identifiers are GIVEN
// (inv.7): this only resolves them against the parsed program, never originates
// them. Java first-party advisories name the sink method by a dotted display form
// ("com.example.web.UrlFetcher.fetch", "UrlFetcher.fetch", or just "fetch"); we
// match each wanted identifier against the symbol's display name, its dotted
// suffixes, and its last-dot leaf. A no-match is an empty result, not an error; a
// load failure is a hard error (inv.4).
func ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	index, err := IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.SymbolResolutionResult{}, err
	}

	wanted := make(map[string]bool, len(req.AdvisorySymbols))
	for _, s := range req.AdvisorySymbols {
		wanted[s] = true
	}

	var resolved []plugin.Symbol
	for _, sym := range index.Symbols {
		if javaSymbolMatches(sym, wanted) {
			resolved = append(resolved, sym)
		}
	}
	return plugin.SymbolResolutionResult{Partiality: index.Partiality, Resolved: resolved}, nil
}

// javaSymbolMatches reports whether sym corresponds to any wanted advisory
// identifier. The symbol's DisplayName is a dot-joined qualified name within its
// package (e.g. "UrlFetcher.fetch(1)"); we also derive its package-qualified form
// ("com.example.web.UrlFetcher.fetch") and its bare leaf ("fetch"). A wanted
// identifier matches if it equals any of those forms, with method arity markers
// ("(1)") tolerated on either side.
func javaSymbolMatches(sym plugin.Symbol, wanted map[string]bool) bool {
	for w := range wanted {
		for _, cand := range javaSymbolForms(sym) {
			if eqIgnoringArity(w, cand) {
				return true
			}
		}
	}
	return false
}

// javaSymbolForms returns the display variants an advisory might name a symbol by:
// the bare display name, the package-qualified display name, and the last-dot
// leaf of the display name.
func javaSymbolForms(sym plugin.Symbol) []string {
	disp := sym.DisplayName
	forms := []string{disp}
	if sym.Package != "" {
		forms = append(forms, sym.Package+"."+disp)
	}
	if i := lastDot(disp); i >= 0 {
		forms = append(forms, disp[i+1:])
	}
	return forms
}

// eqIgnoringArity compares two symbol identifiers, ignoring a trailing arity
// marker ("name(2)" or "name()") on either operand so an advisory may name the
// method with or without an arity hint.
func eqIgnoringArity(a, b string) bool {
	return stripArity(a) == stripArity(b) || a == b
}

// stripArity removes a trailing "(...)" arity marker from a method identifier:
// "fetch(1)" → "fetch", "doGet()" → "doGet". A name with no parens is returned
// unchanged.
func stripArity(s string) string {
	if i := indexByteRune(s, '('); i >= 0 {
		return s[:i]
	}
	return s
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

func indexByteRune(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
