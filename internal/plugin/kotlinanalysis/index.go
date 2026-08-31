package kotlinanalysis

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// IndexSymbols emits one canonical plugin.Symbol per first-party type, method, and
// constructor found in the compiled build output. Because the source is bytecode, the
// emitted identities are JVM-canonical — the same a Java caller observes — which is what
// makes the Kotlin index interop-compatible (K4).
//
// Honest-absent (inv.5): a missing/unreadable build dir is a hard error (loadProgram);
// a present tree with NO compiled build output is a DECLARED partiality
// (tool_failure:no_build_output) carrying an empty symbol set — never a confident-empty
// "this project has no symbols".
func IndexSymbols(_ context.Context, req plugin.IndexSymbolsRequest) (plugin.SymbolIndexResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.SymbolIndexResult{}, err
	}

	var syms []plugin.Symbol
	packages := map[string]bool{}
	for _, c := range prog.classes {
		typeSym := SymbolFromClass(c)
		if typeSym.Package != "" && !packages[typeSym.Package] {
			packages[typeSym.Package] = true
			syms = append(syms, plugin.Symbol{
				Kind:        plugin.SymbolKindPackage,
				Package:     typeSym.Package,
				DisplayName: typeSym.Package,
				SCIP:        "kotlin:pkg:" + typeSym.Package,
			})
		}
		syms = append(syms, typeSym)
		for _, m := range c.Methods {
			// <clinit> is the static-initializer synthetic; it carries no source-level
			// identity a consumer resolves against, so it is omitted from the index.
			if m.Ref.Name == "<clinit>" {
				continue
			}
			syms = append(syms, SymbolFromMethodRef(m.Ref))
		}
	}

	sort.Slice(syms, func(i, j int) bool { return syms[i].SCIP < syms[j].SCIP })
	return plugin.SymbolIndexResult{
		Partiality: prog.partiality(),
		Symbols:    syms,
	}, nil
}
