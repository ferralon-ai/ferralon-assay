package jsanalysis

import (
	"context"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// FindIngresses identifies framework-idiomatic entry points in the JS/TS module at
// req.BuildDir: Express/Koa route registrations (app.get/post/use, router.get/...)
// and Node http.createServer handlers whose handler argument is a NAMED function
// reference, and Next.js-style default-export request handlers. Each ingress symbol
// is the HANDLER function's SCIP id — the SAME id the call graph and symbol resolver
// emit for that function, so the pipeline's firstPartyReachPaths BFS can connect an
// ingress to a reachable sink. An anonymous (inline-arrow) handler records no
// ingress (honest absence, never a fabricated entry). A missing build dir is a hard
// error (inv.4).
func FindIngresses(_ context.Context, req plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.IngressResult{}, err
	}

	seen := map[string]bool{}
	var ingresses []plugin.Ingress
	for _, f := range prog.files {
		for _, in := range f.ingresses {
			sym := prog.resolveIngressSymbol(f.module, in)
			if sym == "" {
				continue
			}
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

	sort.Slice(ingresses, func(i, j int) bool {
		if ingresses[i].Kind != ingresses[j].Kind {
			return ingresses[i].Kind < ingresses[j].Kind
		}
		if ingresses[i].Symbol != ingresses[j].Symbol {
			return ingresses[i].Symbol < ingresses[j].Symbol
		}
		return ingresses[i].Selector < ingresses[j].Selector
	})

	return plugin.IngressResult{Partiality: ingressPartiality(prog), Ingresses: ingresses}, nil
}

// ingressPartiality declares completeness of ingress discovery. The lexical scanner
// cannot see middleware-mounted routers without a named handler, or dynamically
// registered handlers, so a skipped construct degrades partiality; a clean parse is
// Complete (the ingresses found ARE complete for the idioms the scanner models).
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
// declared JS/TS symbols in the build dir. The advisory identifiers are GIVEN
// (inv.7): this only resolves them against the parsed program, never originates
// them. JS first-party advisories name the sink function by a dotted display form
// ("util/fetcher.fetchUrl", "fetchUrl", or "Fetcher.fetch"); we match each wanted
// identifier against the symbol's display name, its module-qualified form, and its
// last-dot leaf, arity-tolerant. A no-match is an empty result, not an error; a load
// failure is a hard error (inv.4).
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
		if jsSymbolMatches(sym, wanted) {
			resolved = append(resolved, sym)
		}
	}
	return plugin.SymbolResolutionResult{Partiality: index.Partiality, Resolved: resolved}, nil
}

// jsSymbolMatches reports whether sym corresponds to any wanted advisory identifier.
// The symbol's DisplayName is a dot-joined qualified name within its module (e.g.
// "fetchUrl(1)" or "Fetcher.fetch(1)"); we also derive its module-qualified form
// ("util/fetcher.fetchUrl") and its bare leaf ("fetchUrl"). A wanted identifier
// matches if it equals any of those forms, with arity markers ("(1)") tolerated on
// either side.
func jsSymbolMatches(sym plugin.Symbol, wanted map[string]bool) bool {
	for w := range wanted {
		for _, cand := range jsSymbolForms(sym) {
			if eqIgnoringArity(w, cand) {
				return true
			}
		}
	}
	return false
}

// jsSymbolForms returns the display variants an advisory might name a symbol by: the
// bare display name, the module-qualified display name (with both '/'-path and the
// module leaf as the qualifier), and the last-dot leaf of the display name.
func jsSymbolForms(sym plugin.Symbol) []string {
	disp := sym.DisplayName
	forms := []string{disp}
	if sym.Package != "" {
		forms = append(forms, sym.Package+"."+disp)
		// also a module-leaf-qualified form ("fetcher.fetchUrl" from module "util/fetcher")
		if i := lastSlash(sym.Package); i >= 0 {
			forms = append(forms, sym.Package[i+1:]+"."+disp)
		}
	}
	if i := lastDot(disp); i >= 0 {
		forms = append(forms, disp[i+1:])
	}
	return forms
}

// eqIgnoringArity compares two symbol identifiers, ignoring a trailing arity marker
// ("name(2)" or "name()") on either operand so an advisory may name the function
// with or without an arity hint.
func eqIgnoringArity(a, b string) bool {
	return stripArity(a) == stripArity(b) || a == b
}

// stripArity removes a trailing "(...)" arity marker from a function identifier:
// "fetch(1)" → "fetch". A name with no parens is returned unchanged.
func stripArity(s string) string {
	if i := strings.IndexByte(s, '('); i >= 0 {
		return s[:i]
	}
	return s
}

func lastDot(s string) int {
	return strings.LastIndexByte(s, '.')
}

func lastSlash(s string) int {
	return strings.LastIndexByte(s, '/')
}
