package pythonanalysis

import (
	"context"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencySymbols maps the advisory's vulnerable symbol(s) to concrete Python
// symbols for the build dir. The advisory identifiers are GIVEN (inv.7): this only
// resolves them against the parsed program, never originates them. A no-match is an empty
// result, not an error; a load failure is a hard error (inv.4).
//
// When the advisory's package is the build's own code (or the request names no pypi
// package), symbols resolve against declared first-party symbols: Python advisories name
// the sink by a dotted import path ("deepdiff.delta.Delta"), a module-qualified function
// ("local_python_executor.evaluate_python_code"), a node/class name ("ACE_ExpressionEval"),
// or a module-leaf-qualified method ("JpegImagePlugin._save"); we match each wanted
// identifier against the symbol's display name, its dotted-module-qualified form, its
// module-leaf-qualified form, and its last-dot leaf, arity-tolerant.
//
// When the package is a dependency, its code is not in the build dir, so a first-party
// symbol that happens to share the name is never the advisory's symbol. The symbol
// resolves only onto a dependency boundary node the call graph actually contains for that
// distribution, matched on the full dotted import path (see resolveBoundary).
func ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	index, err := IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.SymbolResolutionResult{}, err
	}

	wanted := make(map[string]bool, len(req.AdvisorySymbols))
	for _, s := range req.AdvisorySymbols {
		wanted[strings.TrimSpace(s)] = true
	}

	var firstParty []plugin.Symbol
	for _, sym := range index.Symbols {
		if pySymbolMatches(sym, wanted) {
			firstParty = append(firstParty, sym)
		}
	}

	dist := pypiDistFromPURL(req.PURL)
	if dist == "" {
		return plugin.SymbolResolutionResult{Partiality: index.Partiality, Resolved: firstParty}, nil
	}
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.SymbolResolutionResult{}, err
	}
	if prog.dists.providesFirstParty(dist) {
		return plugin.SymbolResolutionResult{Partiality: index.Partiality, Resolved: firstParty}, nil
	}

	res := resolveBoundary(callGraphOf(prog), dist, req.AdvisorySymbols)
	res.Partiality = index.Partiality
	return res, nil
}

// resolveBoundary maps each advisory symbol onto a boundary node of dist present in the
// call graph, by exact dotted-path equality (arity-tolerant). A re-export form
// ("jwt.encode" for "jwt.api_jwt.encode") is not matched: the distribution's import map
// names only its top-level packages, so nothing here justifies equating two paths. The
// package identity of every resolved node is its import binding's distribution, recorded
// in Origins.
func resolveBoundary(cg plugin.CallGraphResult, dist string, advisory []string) plugin.SymbolResolutionResult {
	type node struct{ id, dist string }
	nodes := map[string]node{} // dotted path → boundary node of dist
	for _, e := range cg.Edges {
		if d, dotted, ok := parseBoundarySCIP(e.Callee.SCIP); ok && d == dist {
			nodes[dotted] = node{id: e.Callee.SCIP, dist: d}
		}
	}
	var res plugin.SymbolResolutionResult
	for _, a := range advisory {
		n, ok := nodes[stripArity(strings.TrimSpace(a))]
		if !ok {
			continue
		}
		if res.Origins == nil {
			res.Origins = map[string]string{}
		}
		if _, dup := res.Origins[n.id]; !dup {
			res.Resolved = append(res.Resolved, sym(n.id))
			res.Origins[n.id] = pypiPURL(n.dist)
		}
	}
	return res
}

// pySymbolMatches reports whether sym corresponds to any wanted advisory identifier,
// tolerating a trailing arity marker on either side.
func pySymbolMatches(sym plugin.Symbol, wanted map[string]bool) bool {
	for w := range wanted {
		if w == "" {
			continue
		}
		for _, cand := range pySymbolForms(sym) {
			if eqIgnoringArity(w, cand) {
				return true
			}
		}
	}
	return false
}

// pySymbolForms returns the dotted import-path variants an advisory might name a symbol
// by: the bare display name ("Delta", "Delta.apply(2)"), the fully dotted
// module-qualified form ("deepdiff.delta.Delta"), the module-leaf-qualified form
// ("delta.Delta", "JpegImagePlugin._save"), and the last-dot leaf of the display
// ("apply"). Python import paths are dot-separated, so the '/'-joined module package is
// converted to dots.
func pySymbolForms(sym plugin.Symbol) []string {
	disp := sym.DisplayName
	forms := []string{disp}
	if sym.Package != "" {
		dotted := strings.ReplaceAll(sym.Package, "/", ".")
		forms = append(forms, dotted+"."+disp)
		if i := strings.LastIndexByte(sym.Package, '/'); i >= 0 {
			forms = append(forms, sym.Package[i+1:]+"."+disp)
		} else {
			// single-segment module ("local_python_executor"): leaf == whole module.
			forms = append(forms, sym.Package+"."+disp)
		}
	}
	if i := strings.LastIndexByte(disp, '.'); i >= 0 {
		forms = append(forms, disp[i+1:])
	}
	return forms
}

// eqIgnoringArity compares two symbol identifiers, ignoring a trailing arity marker
// ("name(2)" / "name()") on either operand so an advisory may name the symbol with or
// without an arity hint.
func eqIgnoringArity(a, b string) bool {
	return stripArity(a) == stripArity(b) || a == b
}

// stripArity removes a trailing "(...)" arity marker from an identifier's LAST segment:
// "Delta.apply(2)" → "Delta.apply". A name with no parens is returned unchanged.
func stripArity(s string) string {
	if i := strings.LastIndexByte(s, '('); i >= 0 {
		return s[:i]
	}
	return s
}
