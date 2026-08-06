package jsanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// jsExtensions are the source extensions the analyzer parses.
var jsExtensions = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true,
}

// IndexSymbols walks the JS/TS sources under req.BuildDir, parses each source file
// for its declared functions and class methods, and emits one stable SCIP-shaped
// Symbol per declaration. Symbols are sorted by SCIP id so the result is
// deterministic.
//
// Hard error vs. partiality (inv.4 / inv.5):
//   - A missing/unreadable build dir, or a build dir containing no JS/TS files at
//     all, is a hard error — never a silent empty success.
//   - A file that cannot be read degrades Partiality to declared-partial
//     (PartialReasonToolFailure). The result NEVER renders an unknown as a complete
//     index.
func IndexSymbols(_ context.Context, req plugin.IndexSymbolsRequest) (plugin.SymbolIndexResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.SymbolIndexResult{}, err
	}

	var syms []plugin.Symbol
	for _, f := range prog.files {
		syms = append(syms, symbolsFromParse(f)...)
	}
	sort.Slice(syms, func(i, j int) bool { return syms[i].SCIP < syms[j].SCIP })

	return plugin.SymbolIndexResult{
		Partiality: indexPartiality(prog.readFailed, prog.skipped),
		Symbols:    syms,
	}, nil
}

// indexPartiality builds the declared partiality for the index. A clean parse of all
// files is Complete; a read failure or a skipped construct is declared partial with
// the matching machine-readable reason(s).
func indexPartiality(readFailed, skipped bool) plugin.Partiality {
	var reasons []string
	if readFailed {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if skipped {
		reasons = append(reasons, plugin.PartialReasonUnsupported)
	}
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(reasons...)
}

// symbolsFromParse converts the declarations of one parsed file into SCIP Symbols.
// The DisplayName is the dot-joined qualified name within the module (e.g.
// "FetchService.handle" for a class method, "handleFetch" for a module function);
// Package is the module path so the resolver can present a module-qualified form.
func symbolsFromParse(f fileParse) []plugin.Symbol {
	out := make([]plugin.Symbol, 0, len(f.decls))
	for _, d := range f.decls {
		switch d.kind {
		case kindFunc:
			out = append(out, plugin.Symbol{
				SCIP:        scipSymbol(f.module, d.enclosing, functionDescriptor(d.name, d.arity)),
				DisplayName: qualifiedDisplay(d.enclosing, functionDisplay(d.name, d.arity)),
				Package:     f.module,
			})
		case kindClass:
			out = append(out, plugin.Symbol{
				SCIP:        scipSymbol(f.module, d.enclosing, d.name+"#"),
				DisplayName: qualifiedDisplay(d.enclosing, d.name),
				Package:     f.module,
			})
		}
	}
	return out
}

// qualifiedDisplay renders a human-readable, dot-joined name, e.g. "Svc.handle" for
// a method on a class, or "handleFetch" for a module-level function.
func qualifiedDisplay(enclosing []string, leaf string) string {
	if len(enclosing) == 0 {
		return leaf
	}
	return strings.Join(enclosing, ".") + "." + leaf
}

// functionDisplay renders a function's leaf display name, appending its arity for
// disambiguation readability, e.g. "handler()" or "handler(2)".
func functionDisplay(name string, arity int) string {
	if arity == 0 {
		return name + "()"
	}
	return fmt.Sprintf("%s(%d)", name, arity)
}

// jsFiles returns every JS/TS source file under root, excluding common
// non-application trees (build output, dependencies, hidden dirs) and declaration
// files (.d.ts, which declare no bodies). The list is sorted for deterministic
// iteration.
func jsFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, ".d.ts") {
			return nil
		}
		if jsExtensions[filepath.Ext(name)] {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// skipDir reports whether a directory should be excluded from the source walk.
func skipDir(name string) bool {
	switch name {
	case "node_modules", "dist", "build", "out", "coverage", ".git", ".next", ".nuxt", "vendor":
		return true
	}
	return strings.HasPrefix(name, ".")
}

// moduleOf returns the module path of a source file: its path relative to the build
// root, '/'-joined, with the source extension stripped. A file at the root with no
// directory prefix yields its base name (without extension). It is the namespace
// component of the file's SCIP ids — stable and offline.
func moduleOf(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	if ext := filepath.Ext(rel); jsExtensions[ext] {
		rel = strings.TrimSuffix(rel, ext)
	}
	return rel
}
