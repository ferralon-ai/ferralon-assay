package dotnetanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// IndexSymbols walks the C# sources under req.BuildDir, parses each source file for its
// declared types (class/struct/interface/record/enum) and methods, and emits one stable
// SCIP-shaped Symbol per declaration. Symbols are sorted by SCIP id so the result is
// deterministic.
//
// Hard error vs. partiality (inv.4 / inv.5):
//   - A missing/unreadable build dir, or a build dir containing no .cs files at all, is a
//     hard error — never a silent empty success.
//   - A file that cannot be read degrades Partiality to declared-partial
//     (PartialReasonToolFailure). A skipped construct degrades to PartialReasonUnsupported.
//     The result NEVER renders an unknown as a complete index.
func IndexSymbols(_ context.Context, req plugin.IndexSymbolsRequest) (plugin.SymbolIndexResult, error) {
	files, readFailed, skipped, err := loadFiles(req.BuildDir)
	if err != nil {
		return plugin.SymbolIndexResult{}, err
	}

	var syms []plugin.Symbol
	for _, f := range files {
		syms = append(syms, symbolsFromParse(f)...)
	}
	sort.Slice(syms, func(i, j int) bool { return syms[i].SCIP < syms[j].SCIP })

	return plugin.SymbolIndexResult{
		Partiality: indexPartiality(readFailed, skipped),
		Symbols:    syms,
	}, nil
}

// loadFiles parses every C# file under buildDir into a slice of parseResults. A
// missing/empty build dir is a hard error (inv.4); a read failure or a skipped construct is
// surfaced via the returned flags (declared partiality).
func loadFiles(buildDir string) (files []parseResult, readFailed, skipped bool, err error) {
	info, statErr := os.Stat(buildDir)
	if statErr != nil {
		return nil, false, false, fmt.Errorf("dotnetanalysis: stat build dir %q: %w", buildDir, statErr)
	}
	if !info.IsDir() {
		return nil, false, false, fmt.Errorf("dotnetanalysis: build dir %q is not a directory", buildDir)
	}
	paths, walkErr := csharpFiles(buildDir)
	if walkErr != nil {
		return nil, false, false, fmt.Errorf("dotnetanalysis: scan %q: %w", buildDir, walkErr)
	}
	if len(paths) == 0 {
		return nil, false, false, fmt.Errorf("dotnetanalysis: no .cs sources under %q", buildDir)
	}
	for _, p := range paths {
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			readFailed = true
			continue
		}
		pr := parseFile(moduleOf(buildDir, p), string(data))
		if pr.skipped {
			skipped = true
		}
		files = append(files, pr)
	}
	return files, readFailed, skipped, nil
}

// indexPartiality builds the declared partiality for the index: a clean parse of all files
// is Complete; a read failure or a skipped construct is declared partial with the matching
// machine-readable reason(s).
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

// symbolsFromParse converts the declarations of one parsed file into SCIP Symbols. The
// DisplayName is the dot-joined qualified name within the namespace (e.g. "ZipEntry.Extract"
// for a method, "ZipEntry" for a type); Package is the dotted namespace so the resolver can
// present a fully namespace-qualified form ("Ionic.Zip.ZipEntry.Extract").
func symbolsFromParse(f parseResult) []plugin.Symbol {
	out := make([]plugin.Symbol, 0, len(f.decls))
	for _, d := range f.decls {
		switch d.kind {
		case kindFunc:
			out = append(out, plugin.Symbol{
				SCIP:        scipSymbol(d.namespace, d.enclosing, functionDescriptor(d.name, d.arity)),
				DisplayName: qualifiedDisplay(d.enclosing, functionDisplay(d.name, d.arity)),
				Package:     d.namespace,
			})
		case kindType:
			out = append(out, plugin.Symbol{
				SCIP:        scipSymbol(d.namespace, d.enclosing, typeDescriptor(d.name)),
				DisplayName: qualifiedDisplay(d.enclosing, d.name),
				Package:     d.namespace,
			})
		}
	}
	return out
}

// qualifiedDisplay renders a human-readable, dot-joined name, e.g. "ZipEntry.Extract" for a
// method on a type, or "ZipEntry" for a top-level type.
func qualifiedDisplay(enclosing []string, leaf string) string {
	if len(enclosing) == 0 {
		return leaf
	}
	return strings.Join(enclosing, ".") + "." + leaf
}

// functionDisplay renders a method's leaf display name, appending its arity for
// disambiguation readability, e.g. "Extract()" or "Extract(2)".
func functionDisplay(name string, arity int) string {
	if arity == 0 {
		return name + "()"
	}
	return fmt.Sprintf("%s(%d)", name, arity)
}

// csharpFiles returns every C# source file under root, excluding common non-application
// trees (build output, packages, VCS, IDE state). The list is sorted for deterministic
// iteration.
func csharpFiles(root string) ([]string, error) {
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
		// Skip generated designer/assembly-info noise that declares no user symbols.
		if strings.HasSuffix(name, ".Designer.cs") || strings.HasSuffix(name, ".g.cs") || strings.HasSuffix(name, ".g.i.cs") {
			return nil
		}
		if filepath.Ext(name) == ".cs" {
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
	case "bin", "obj", "packages", ".git", ".vs", ".vscode", "node_modules", "TestResults":
		return true
	}
	return strings.HasPrefix(name, ".") && name != "."
}

// moduleOf returns the module path of a C# source file: its path relative to the build
// root, '/'-joined, with the ".cs" extension stripped. It is informational provenance (the
// SCIP identity is keyed on the C# namespace, not the file path).
func moduleOf(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	return strings.TrimSuffix(rel, ".cs")
}
