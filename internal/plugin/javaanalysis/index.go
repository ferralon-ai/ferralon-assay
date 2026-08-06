package javaanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// IndexSymbols walks the Java sources under req.BuildDir, parses each .java file
// for its declared types/methods/fields, and emits one stable SCIP Symbol per
// declaration. Symbols are sorted by SCIP id so the result is deterministic.
//
// Hard error vs. partiality (inv.4 / inv.5):
//   - A missing/unreadable build dir, or a build dir containing no .java files at
//     all, is a hard error — never a silent empty success.
//   - A file that cannot be read, or a parse that had to skip a construct it does
//     not model, degrades Partiality to declared-partial (PartialReasonToolFailure
//     for read failures, PartialReasonUnsupported for skipped constructs). The
//     result NEVER renders an unknown as a complete index.
func IndexSymbols(_ context.Context, req plugin.IndexSymbolsRequest) (plugin.SymbolIndexResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.SymbolIndexResult{}, fmt.Errorf("javaanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.SymbolIndexResult{}, fmt.Errorf("javaanalysis: build dir %q is not a directory", req.BuildDir)
	}

	files, err := javaFiles(req.BuildDir)
	if err != nil {
		return plugin.SymbolIndexResult{}, fmt.Errorf("javaanalysis: scan %q: %w", req.BuildDir, err)
	}
	if len(files) == 0 {
		return plugin.SymbolIndexResult{}, fmt.Errorf("javaanalysis: no .java sources under %q", req.BuildDir)
	}

	var (
		syms       []plugin.Symbol
		readFailed bool
		skipped    bool
	)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			readFailed = true
			continue
		}
		pr := parseFile(string(data))
		if pr.skipped {
			skipped = true
		}
		syms = append(syms, symbolsFromParse(pr)...)
	}

	sort.Slice(syms, func(i, j int) bool { return syms[i].SCIP < syms[j].SCIP })

	return plugin.SymbolIndexResult{
		Partiality: indexPartiality(readFailed, skipped),
		Symbols:    syms,
	}, nil
}

// indexPartiality builds the declared partiality for the index. A clean parse of
// all files is Complete; a read failure or a skipped construct is declared
// partial with the matching machine-readable reason(s).
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

// symbolsFromParse converts the declarations of one parsed file into SCIP
// Symbols. Methods carry arity-disambiguated descriptors; the Package field is
// the dotted Java package ("" for the default package).
func symbolsFromParse(pr parseResult) []plugin.Symbol {
	out := make([]plugin.Symbol, 0, len(pr.decls))
	for _, d := range pr.decls {
		var descriptor, display string
		switch d.kind {
		case kindType:
			descriptor = typeDescriptor(d.name)
			display = qualifiedDisplay(d.enclosing, d.name)
		case kindMethod:
			descriptor = methodDescriptor(d.name, d.arity)
			display = qualifiedDisplay(d.enclosing, methodDisplay(d.name, d.arity))
		case kindField:
			descriptor = fieldDescriptor(d.name)
			display = qualifiedDisplay(d.enclosing, d.name)
		default:
			continue
		}
		out = append(out, plugin.Symbol{
			SCIP:        scipSymbol(pr.pkg, d.enclosing, descriptor),
			DisplayName: display,
			Package:     pr.pkg,
		})
	}
	return out
}

// qualifiedDisplay renders a human-readable, dot-joined name, e.g.
// "Service.handle" for a method on a top-level type or "Outer.Inner" for a nested
// type.
func qualifiedDisplay(enclosing []string, leaf string) string {
	if len(enclosing) == 0 {
		return leaf
	}
	return strings.Join(enclosing, ".") + "." + leaf
}

// methodDisplay renders a method's leaf display name, appending its arity for
// overloaded readability, e.g. "handle()" or "handle(2)".
func methodDisplay(name string, arity int) string {
	if arity == 0 {
		return name + "()"
	}
	return fmt.Sprintf("%s(%d)", name, arity)
}

// javaFiles returns every .java file under root, excluding common
// non-application trees (build output, hidden dirs) so the index reflects real
// source. The list is sorted for deterministic iteration.
func javaFiles(root string) ([]string, error) {
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
		if strings.HasSuffix(d.Name(), ".java") {
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
	case "target", "build", "out", "bin", ".git", ".gradle", "node_modules":
		return true
	}
	return strings.HasPrefix(name, ".")
}
