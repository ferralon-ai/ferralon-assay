package pythonanalysis

import (
	"context"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencySymbols maps the advisory's vulnerable symbol(s) to concrete declared
// Python symbols in the build dir. The advisory identifiers are GIVEN (inv.7): this only
// resolves them against the parsed program, never originates them. Python advisories name
// the sink by a dotted import path ("deepdiff.delta.Delta"), a module-qualified function
// ("local_python_executor.evaluate_python_code"), a node/class name ("ACE_ExpressionEval"),
// or a module-leaf-qualified method ("JpegImagePlugin._save"); we match each wanted
// identifier against the symbol's display name, its dotted-module-qualified form, its
// module-leaf-qualified form, and its last-dot leaf, arity-tolerant. A no-match is an
// empty result, not an error; a load failure is a hard error (inv.4).
func ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	index, err := IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.SymbolResolutionResult{}, err
	}

	wanted := make(map[string]bool, len(req.AdvisorySymbols))
	for _, s := range req.AdvisorySymbols {
		wanted[strings.TrimSpace(s)] = true
	}

	var resolved []plugin.Symbol
	for _, sym := range index.Symbols {
		if pySymbolMatches(sym, wanted) {
			resolved = append(resolved, sym)
		}
	}
	return plugin.SymbolResolutionResult{Partiality: index.Partiality, Resolved: resolved}, nil
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
