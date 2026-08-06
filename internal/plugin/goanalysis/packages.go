// Package goanalysis is the in-process Go analysis engine that backs the
// tegron-plugin-go subprocess. It loads the target program with go/packages +
// go/types, emits stable SCIP symbol identities from the loaded program (no
// scip-go dependency), and answers the IndexSymbols / ResolveDependencySymbols
// operations of the LanguagePlugin contract in the plugin package.
//
// Import boundary (inv.8): this sub-package MAY import internal/plugin for the
// shared value types and MAY link golang.org/x/tools. The FORBIDDEN edge is the
// reverse one — internal/plugin MUST NOT import goanalysis — so the heavy
// analysis libraries link only into the subprocess binary, never into tegrond.
package goanalysis

import (
	"context"
	"fmt"
	"go/types"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// loadMode is the go/packages mode covering names, files, types, syntax, type
// info, and the dependency/import/module graph — everything the SCIP emitter and
// the symbol walk need from a single offline load.
const loadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedDeps |
	packages.NeedImports |
	packages.NeedModule

// LoadResult holds the loaded program plus a partiality declaration describing
// whether the load was fully clean. A genuine load failure (broken module,
// missing build dir) is a hard error (inv.4), returned as the error; per-package
// type-check errors that still yield usable type info degrade Partiality instead.
type LoadResult struct {
	Packages   []*packages.Package
	Partiality plugin.Partiality
}

// LoadProgram loads the buildable module rooted at buildDir with full type and
// syntax information, offline. A failure to invoke the loader, or a load that
// returns no packages, is a hard error (inv.4) — never a silent empty result.
// Per-package errors that still produce type info are surfaced as degraded
// partiality (PartialReasonToolFailure) on the LoadResult.
func LoadProgram(ctx context.Context, buildDir string) (*LoadResult, error) {
	cfg := &packages.Config{
		Mode:    loadMode,
		Context: ctx,
		Dir:     buildDir,
		Tests:   false,
		// The analyzed target is the buildDir's own module — NEVER a member of any
		// workspace the analyzer process itself happens to run inside (e.g. Tegron's
		// own go.work during development). Force GOWORK=off so the load resolves the
		// target module standalone; an ambient go.work would otherwise make
		// packages.Load try to resolve the target against the wrong module graph and
		// return an empty/garbled program.
		Env: append(os.Environ(), "GOWORK=off"),
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("go/packages load %q: %w", buildDir, err)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("go/packages load %q: no packages found", buildDir)
	}

	part := plugin.Complete()
	var loadErrs []string
	for _, p := range pkgs {
		for _, e := range p.Errors {
			loadErrs = append(loadErrs, e.Error())
		}
	}
	// If a package failed so hard it produced no type information, the load is
	// not usable — treat it as a hard error (the module does not type-check).
	for _, p := range pkgs {
		if p.Types == nil {
			return nil, fmt.Errorf("go/packages load %q: package %q has no type info: %s",
				buildDir, p.PkgPath, strings.Join(loadErrs, "; "))
		}
	}
	if len(loadErrs) > 0 {
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}

	return &LoadResult{Packages: pkgs, Partiality: part}, nil
}

// SCIPString emits a stable, version-qualified SCIP symbol string for obj in
// pkg, derived purely from go/types (no scip-go dependency).
//
// Grammar (the standard SCIP symbol scheme, space-separated):
//
//	scip-go gomod <module-path> <version> <descriptors>
//
// where the leading fields identify the package's owning module (manager gomod)
// and <descriptors> is a sequence of SCIP descriptors with these suffixes:
//
//	<pkg-path>/      namespace descriptor — the full import path of the package
//	<name>#          type descriptor — a named type
//	<recv>#<name>(). method descriptor — a method, qualified by its receiver type
//	<name>().        function descriptor — a package-level func
//	<name>.          term descriptor — a const/var/field, or fallback
//
// The string is deterministic for a given object (no maps, no addresses) and
// unique per object: distinct objects in the same package differ in their final
// descriptor; objects in different packages differ in the namespace descriptor;
// objects in different module versions differ in the version field. When the
// module/version is unknown (e.g. the std synthetic package), placeholders
// "stdlib" / "." keep the string well-formed and stable.
func SCIPString(pkg *types.Package, obj types.Object) string {
	module, version := moduleVersion(pkg, obj)
	pkgPath := "."
	if p := objPackage(pkg, obj); p != nil {
		pkgPath = p.Path()
	}

	var desc strings.Builder
	desc.WriteString(pkgPath)
	desc.WriteString("/")
	desc.WriteString(symbolDescriptor(obj))

	return fmt.Sprintf("scip-go gomod %s %s %s", module, version, desc.String())
}

// symbolDescriptor renders the trailing per-object descriptor(s).
func symbolDescriptor(obj types.Object) string {
	switch o := obj.(type) {
	case *types.TypeName:
		return o.Name() + "#"
	case *types.Func:
		sig, _ := o.Type().(*types.Signature)
		if sig != nil && sig.Recv() != nil {
			recv := receiverTypeName(sig.Recv().Type())
			return recv + "#" + o.Name() + "()."
		}
		return o.Name() + "()."
	case *types.Var:
		return o.Name() + "."
	case *types.Const:
		return o.Name() + "."
	default:
		return obj.Name() + "."
	}
}

// receiverTypeName returns the bare named-type name of a method receiver,
// stripping any pointer indirection so (*T) and T share a stable receiver token.
func receiverTypeName(t types.Type) string {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		return named.Obj().Name()
	}
	return t.String()
}

// objPackage returns the package an object belongs to, falling back to pkg when
// the object carries no package (e.g. builtins).
func objPackage(pkg *types.Package, obj types.Object) *types.Package {
	if obj.Pkg() != nil {
		return obj.Pkg()
	}
	return pkg
}

// moduleVersion derives the (module-path, version) pair for the object's package.
// go/packages attaches Module info to loaded packages; SCIPString receives only
// *types.Package, so we encode identity from the package path and accept a
// "stdlib"/"." placeholder when no module metadata is reachable. The IndexSymbols
// walk (which holds the *packages.Package) supplies precise module/version.
func moduleVersion(pkg *types.Package, obj types.Object) (string, string) {
	p := objPackage(pkg, obj)
	if p == nil {
		return "stdlib", "."
	}
	return p.Path(), "."
}

// scipFromPackage emits a SCIP string using the loaded *packages.Package so the
// module path and version come from real module metadata rather than the
// path-derived placeholder. It is the IndexSymbols-internal precise emitter.
func scipFromPackage(p *packages.Package, obj types.Object) string {
	module := p.PkgPath
	version := "."
	if p.Module != nil {
		if p.Module.Path != "" {
			module = p.Module.Path
		}
		if p.Module.Version != "" {
			version = p.Module.Version
		}
	}
	pkgPath := p.PkgPath
	if obj.Pkg() != nil {
		pkgPath = obj.Pkg().Path()
	}
	return fmt.Sprintf("scip-go gomod %s %s %s/%s", module, version, pkgPath, symbolDescriptor(obj))
}

// IndexSymbols loads the program and emits a Symbol per exported (and
// reachable-internal package-scope) object across every loaded package,
// including the methods of exported named types. Partiality is Complete unless
// the load was degraded.
func IndexSymbols(ctx context.Context, req plugin.IndexSymbolsRequest) (plugin.SymbolIndexResult, error) {
	res, err := LoadProgram(ctx, req.BuildDir)
	if err != nil {
		return plugin.SymbolIndexResult{}, err
	}

	var syms []plugin.Symbol
	for _, p := range res.Packages {
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if !includeObject(obj) {
				continue
			}
			syms = append(syms, plugin.Symbol{
				SCIP:        scipFromPackage(p, obj),
				DisplayName: displayName(obj),
				Package:     p.PkgPath,
			})
			syms = append(syms, methodSymbols(p, obj)...)
		}
	}

	sort.Slice(syms, func(i, j int) bool { return syms[i].SCIP < syms[j].SCIP })
	return plugin.SymbolIndexResult{Partiality: res.Partiality, Symbols: syms}, nil
}

// includeObject reports whether a package-scope object should be indexed. We
// index exported objects (the dependency-facing surface), plus first-party funcs
// in package main — the entry point AND unexported handlers/sinks that a
// first-party advisory names (e.g. main.fetchHandler). govulncheck never traces a
// first-party sink, so reachability_ingress falls back to the call graph toward
// these symbols; they must be indexed for that fallback to resolve.
func includeObject(obj types.Object) bool {
	if obj == nil {
		return false
	}
	if obj.Exported() {
		return true
	}
	if fn, ok := obj.(*types.Func); ok {
		if fn.Name() == "main" {
			return true
		}
		// Unexported func in package main: first-party sink/handler surface.
		if pkg := fn.Pkg(); pkg != nil && pkg.Name() == "main" {
			return true
		}
	}
	return false
}

// methodSymbols emits Symbols for the exported methods of an exported named type.
func methodSymbols(p *packages.Package, obj types.Object) []plugin.Symbol {
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return nil
	}
	named, ok := tn.Type().(*types.Named)
	if !ok {
		return nil
	}
	// Walk the pointer method set so both value and pointer methods are covered.
	ms := types.NewMethodSet(types.NewPointer(named))
	var out []plugin.Symbol
	for i := 0; i < ms.Len(); i++ {
		m := ms.At(i).Obj()
		if !m.Exported() {
			continue
		}
		out = append(out, plugin.Symbol{
			SCIP:        scipFromPackage(p, m),
			DisplayName: displayName(m),
			Package:     p.PkgPath,
		})
	}
	return out
}

// displayName renders a human-readable identifier, e.g. "(*Service).Handle" for
// a method or "New" for a package-level func.
func displayName(obj types.Object) string {
	if fn, ok := obj.(*types.Func); ok {
		if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
			return fmt.Sprintf("(%s).%s", recvDisplay(sig.Recv().Type()), fn.Name())
		}
	}
	return obj.Name()
}

func recvDisplay(t types.Type) string {
	if ptr, ok := t.(*types.Pointer); ok {
		if named, ok := ptr.Elem().(*types.Named); ok {
			return "*" + named.Obj().Name()
		}
	}
	if named, ok := t.(*types.Named); ok {
		return named.Obj().Name()
	}
	return t.String()
}

// ResolveDependencySymbols indexes the program and filters the index to objects
// matching the advisory's PURL package and AdvisorySymbols. The advisory
// identifiers are GIVEN (inv.7) — this function never originates them, it only
// resolves them against the loaded program. A no-match is an empty result, not
// an error; a load failure is a hard error (inv.4).
func ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	index, err := IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.SymbolResolutionResult{}, err
	}

	pkgFilter := packageFromPURL(req.PURL)
	wanted := make(map[string]bool, len(req.AdvisorySymbols))
	for _, s := range req.AdvisorySymbols {
		wanted[s] = true
	}

	// The PURL package filter only applies when the advisory names a real, loaded
	// package — the dependency case. A FIRST-PARTY advisory carries a synthetic PURL
	// (pkg:golang/<app>) that is NOT a loaded package path (the repro's module path is
	// its own, e.g. tegron.corpus/<repro>), so an exact-path filter would drop every
	// candidate. When the filter matches no loaded package, drop it and resolve the
	// advisory symbols by name across the program — sound because AdvisorySymbols are
	// still the GIVEN ground truth (inv.7); we only relax the package SCOPE, never the
	// symbol identity.
	if pkgFilter != "" {
		present := false
		for _, sym := range index.Symbols {
			if sym.Package == pkgFilter {
				present = true
				break
			}
		}
		if !present {
			pkgFilter = ""
		}
	}

	var resolved []plugin.Symbol
	for _, sym := range index.Symbols {
		if pkgFilter != "" && sym.Package != pkgFilter {
			continue
		}
		if !matchesAdvisorySymbol(sym, wanted) {
			continue
		}
		resolved = append(resolved, sym)
	}

	return plugin.SymbolResolutionResult{Partiality: index.Partiality, Resolved: resolved}, nil
}

// packageFromPURL extracts the import path from a Go PURL of the form
// pkg:golang/<import-path>[@version]. An empty or non-golang PURL yields "" (no
// package filter), so resolution falls back to matching by symbol name alone.
func packageFromPURL(purl string) string {
	const prefix = "pkg:golang/"
	if !strings.HasPrefix(purl, prefix) {
		return ""
	}
	path := strings.TrimPrefix(purl, prefix)
	if at := strings.IndexByte(path, '@'); at >= 0 {
		path = path[:at]
	}
	return path
}

// matchesAdvisorySymbol reports whether sym corresponds to any of the wanted
// advisory symbol identifiers. Advisory symbols are bare names ("Sink"),
// receiver-qualified ("Service.Handle" / "(*Service).Handle"), or
// package-qualified ("main.fetchHandler") — the form a first-party advisory uses
// for a func in package main. We compare the wanted identifiers AND their
// last-dot leaf (the package-qualifier stripped, e.g. "main.fetchHandler" →
// "fetchHandler") against the display name, its leaf, and its paren-stripped form.
func matchesAdvisorySymbol(sym plugin.Symbol, wanted map[string]bool) bool {
	// Candidate display forms for this symbol.
	disp := sym.DisplayName
	leaf := disp
	if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
		leaf = leaf[i+1:]
	}
	leaf = strings.TrimSuffix(leaf, ")")
	norm := strings.NewReplacer("(*", "", "(", "", ")", "").Replace(disp)

	for w := range wanted {
		// Strip a leading "<pkg>." qualifier off the advisory identifier so the
		// package-qualified first-party form lines up with the package-less display.
		wLeaf := w
		if i := strings.LastIndexByte(wLeaf, '.'); i >= 0 {
			wLeaf = wLeaf[i+1:]
		}
		if w == disp || w == leaf || w == norm || wLeaf == disp || wLeaf == leaf || wLeaf == norm {
			return true
		}
	}
	return false
}
