package dotnetanalysis

import (
	"context"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencySymbols maps the advisory's vulnerable symbol(s) to concrete declared C#
// symbols in the build dir. The advisory identifiers are GIVEN (inv.7): this only resolves
// them against the parsed program, never originates them. .NET advisories name the sink by a
// namespace-qualified dotted name ("Ionic.Zip.ZipEntry.Extract"), a type-qualified method
// ("ZipEntry.Extract"), a namespace-leaf-qualified form ("Zip.ZipEntry.Extract"), or a bare
// leaf ("Extract"); we match each wanted identifier against those forms, arity-tolerant and
// CASE-INSENSITIVE (a NuGet advisory may carry a cross-language lower-cased method name such
// as "Ecdsa.verify" for the C# "Ecdsa.Verify"). A no-match is an empty result, not an error;
// a load failure is a hard error (inv.4).
func ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	index, err := IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.SymbolResolutionResult{}, err
	}

	wanted := make([]string, 0, len(req.AdvisorySymbols))
	for _, s := range req.AdvisorySymbols {
		if t := strings.TrimSpace(s); t != "" {
			wanted = append(wanted, t)
		}
	}

	var resolved []plugin.Symbol
	for _, sym := range index.Symbols {
		if dotnetSymbolMatches(sym, wanted) {
			resolved = append(resolved, sym)
		}
	}
	return plugin.SymbolResolutionResult{Partiality: index.Partiality, Resolved: resolved}, nil
}

// dotnetSymbolMatches reports whether sym corresponds to any wanted advisory identifier,
// tolerating a trailing arity marker on either side and comparing case-insensitively.
func dotnetSymbolMatches(sym plugin.Symbol, wanted []string) bool {
	forms := dotnetSymbolForms(sym)
	for _, w := range wanted {
		for _, cand := range forms {
			if eqIgnoringArityCI(w, cand) {
				return true
			}
		}
	}
	return false
}

// dotnetSymbolForms returns the dotted variants an advisory might name a symbol by: the bare
// display name ("ZipEntry.Extract(1)"), the fully namespace-qualified form
// ("Ionic.Zip.ZipEntry.Extract(1)"), the namespace-leaf-qualified form
// ("Zip.ZipEntry.Extract(1)"), and the last-dot leaf of the display ("Extract(1)").
func dotnetSymbolForms(sym plugin.Symbol) []string {
	disp := sym.DisplayName
	forms := []string{disp}
	if sym.Package != "" {
		forms = append(forms, sym.Package+"."+disp)
		if i := strings.LastIndexByte(sym.Package, '.'); i >= 0 {
			forms = append(forms, sym.Package[i+1:]+"."+disp)
		}
	}
	if i := strings.LastIndexByte(disp, '.'); i >= 0 {
		forms = append(forms, disp[i+1:])
	}
	return forms
}

// eqIgnoringArityCI compares two symbol identifiers case-insensitively, ignoring a trailing
// arity marker ("name(2)" / "name()") on either operand so an advisory may name the symbol
// with or without an arity hint and with cross-language casing.
func eqIgnoringArityCI(a, b string) bool {
	la, lb := strings.ToLower(a), strings.ToLower(b)
	return la == lb || stripArity(la) == stripArity(lb)
}

// stripArity removes a trailing "(...)" arity marker from an identifier's LAST segment:
// "ZipEntry.Extract(1)" → "ZipEntry.Extract". A name with no parens is returned unchanged.
func stripArity(s string) string {
	if i := strings.LastIndexByte(s, '('); i >= 0 {
		return s[:i]
	}
	return s
}
