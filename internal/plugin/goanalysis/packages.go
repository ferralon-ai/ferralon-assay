// Package goanalysis is the in-process Go analysis engine that backs the
// assay-plugin-go subprocess. It loads the target program with go/packages +
// go/types, emits stable SCIP symbol identities from the loaded program (no
// scip-go dependency), and answers the IndexSymbols / ResolveDependencySymbols
// operations of the LanguagePlugin contract in the plugin package.
//
// Import boundary (inv.8): this sub-package MAY import internal/plugin for the
// shared value types and MAY link golang.org/x/tools. The FORBIDDEN edge is the
// reverse one — internal/plugin MUST NOT import goanalysis — so the heavy
// analysis libraries link only into the subprocess binary, never into the host binary.
package goanalysis

import (
	"context"
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// sym wraps a bare emitted SCIP id string into a plugin.Symbol at the graph mint
// sites (call-graph edges/roots, ingresses, reach/taint paths). It sets SCIP and
// DisplayName to the SAME id and leaves every structured field (Kind/Package/
// Enclosing/Name/Descriptor/Generated) zero. Because plugin.Symbol is compared by
// == across ALL fields (map keys, [2]Symbol composite keys, set membership), every
// mint from a bare id MUST go through this one helper: two sites that populated
// DisplayName differently would produce Symbols that never compare equal and would
// silently break the reach/taint edge lookups. The index-side mints (IndexSymbols/
// methodSymbols) carry a REAL DisplayName/Package and intentionally do NOT use this.
func sym(s string) plugin.Symbol { return plugin.Symbol{SCIP: s, DisplayName: s} }

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
		// workspace the analyzer process itself happens to run inside (e.g. an
		// enclosing repository's go.work during development). Force GOWORK=off so the load resolves the
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
	var reasons []string
	if len(loadErrs) > 0 {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if droppedCgo(pkgs, cfg.Env) {
		reasons = append(reasons, plugin.PartialReasonCgo)
	}
	if len(reasons) > 0 {
		part = plugin.Partial(reasons...)
	}

	return &LoadResult{Packages: pkgs, Partiality: part}, nil
}

// droppedCgo reports whether the build left out a cgo file of a non-standard-library package
// because cgo is disabled (CGO_ENABLED=0, or no C compiler). Such a file is in no package's
// syntax, so neither the call graph nor govulncheck sees the calls it makes, and runtime/cgo never
// enters the program to trip the cgo detector. A file the build would leave out with cgo enabled
// too (another GOOS, a build tag) is not counted.
//
// The standard library's own cgo variants (net, os/user) are not checked: their pure-Go
// fallbacks are what the build compiles, and the analysis reads those.
//
// The files are matched under the build tags GOFLAGS sets in env, the tags the load ran with.
func droppedCgo(pkgs []*packages.Package, env []string) bool {
	ctx := build.Default
	ctx.CgoEnabled = true
	ctx.BuildTags = goflagsTags(env)
	found := false
	packages.Visit(pkgs, func(p *packages.Package) bool {
		if found || p.Module == nil {
			return !found
		}
		for _, path := range p.IgnoredFiles {
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				continue
			}
			if importsC(path) {
				if ok, err := ctx.MatchFile(filepath.Dir(path), filepath.Base(path)); err == nil && ok {
					found = true
					return false
				}
			}
		}
		return true
	}, nil)
	return found
}

// importsC reports whether the Go file at path imports "C". An unreadable file counts: it may.
func importsC(path string) bool {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return true
	}
	for _, imp := range f.Imports {
		if imp.Path.Value == `"C"` {
			return true
		}
	}
	return false
}

// goflagsTags returns the build tags the last -tags flag in env's GOFLAGS sets. Every go command
// the analysis spawns inherits GOFLAGS, so these are the tags it builds with.
func goflagsTags(env []string) []string {
	var tags []string
	for _, f := range strings.Fields(envOr(env, "GOFLAGS", "")) {
		f = strings.TrimPrefix(strings.TrimPrefix(f, "-"), "-")
		if v, ok := strings.CutPrefix(f, "tags="); ok {
			tags = strings.FieldsFunc(v, func(r rune) bool { return r == ',' })
		}
	}
	return tags
}

// leftOutCallers reports whether a non-test Go file the build left out of a non-standard-library
// package (one for another GOOS or GOARCH, or behind a build tag) may call into module. No
// package's syntax holds such a file, so govulncheck traced no call from it, yet a build for that
// platform or with that tag compiles it.
//
// A file may call into a module when it imports a package of module, a loaded package that imports
// one, or a package the build did not load whose module is module, holds it, or requires it in the
// module graph. A file that cannot be read counts, as does an unloaded import when the module graph
// cannot be read or holds no module for it. A file constrained by the ignore tag is never built and does
// not count.
//
// When module is the standard library, the packages that count are its vulnerable ones (vulnerable,
// or every standard-library package when that is empty), and a file counts when it imports one
// directly or through other packages. A loaded import is followed through the load. An unloaded
// standard-library import is followed through the imports `go list` resolves for it under the
// scan's own GOOS and the common ports, and counts when no port lists it cleanly; an unloaded
// import from any module counts outright.
func leftOutCallers(ctx context.Context, pkgs []*packages.Package, module string, vulnerable []string, buildDir string, env []string) bool {
	reach := newModuleReach(pkgs, module, vulnerable)
	stdlib := module == "stdlib"
	var graph modGraph
	var graphErr error
	graphRead := false
	deps := importGraph{}
	listed := map[string]bool{}
	mayCall := func(imp string) bool {
		if p, ok := reach.loaded[imp]; ok {
			return reach.reachesModule(p)
		}
		if reach.inModule(imp, nil) {
			return true
		}
		if imp == "C" {
			return false
		}
		if stdlib {
			// Which imports a module's package resolves turns on the left-out file's own tags and
			// GOOS, which no listing here reproduces, so any module the build did not load counts.
			if !isStdlibPath(imp, reach.modules) {
				return true
			}
			clean, ok := listed[imp]
			if !ok {
				clean = deps.list(ctx, buildDir, env, imp)
				listed[imp] = clean
			}
			return !clean || deps.reaches(imp, func(path string) bool { return reach.inModule(path, reach.loaded[path]) })
		}
		if isStdlibPath(imp, reach.modules) {
			return false
		}
		if !graphRead {
			graph, graphErr = readModGraph(ctx, buildDir, env)
			graphRead = true
		}
		if graphErr != nil {
			return true
		}
		owner := graph.owner(imp, reach.modules)
		return owner == "" || underModule(module, owner) || graph.requires(owner, module)
	}

	// leftOut reports whether the non-test Go file at path may call into module.
	leftOut := func(path string) bool {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return false
		}
		imports, never, err := fileImports(path)
		if err != nil {
			return true
		}
		return !never && slices.ContainsFunc(imports, mayCall)
	}

	found := false
	loadedDirs := map[string]bool{}
	mainDir := ""
	packages.Visit(pkgs, func(p *packages.Package) bool {
		if found || p.Module == nil {
			return !found
		}
		if p.Module.Main && mainDir == "" {
			mainDir = p.Module.Dir
		}
		for _, files := range [][]string{p.GoFiles, p.OtherFiles, p.IgnoredFiles} {
			for _, f := range files {
				loadedDirs[filepath.Dir(f)] = true
			}
		}
		found = slices.ContainsFunc(p.IgnoredFiles, leftOut)
		return !found
	}, nil)
	if found {
		return true
	}
	if mainDir == "" {
		mainDir = buildDir
	}
	return firstPartyLeftOut(mainDir, loadedDirs, leftOut)
}

// moduleReach answers, over the load's own import graph, whether a package is or imports one of a
// refuted module's packages that count. For the standard library those are its vulnerable packages
// (vulnerable, or every standard-library package when that is empty).
type moduleReach struct {
	module     string
	vulnerable []string
	loaded     map[string]*packages.Package
	modules    map[string]bool
	reaches    map[*packages.Package]bool
}

func newModuleReach(pkgs []*packages.Package, module string, vulnerable []string) *moduleReach {
	r := &moduleReach{
		module:     module,
		vulnerable: vulnerable,
		loaded:     map[string]*packages.Package{},
		modules:    map[string]bool{},
		reaches:    map[*packages.Package]bool{},
	}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		r.loaded[p.PkgPath] = p
		if p.Module != nil {
			r.modules[p.Module.Path] = true
		}
	})
	return r
}

// inModule reports whether the package at path, loaded as p or not loaded (nil), is one of the
// refuted module's packages that count.
func (r *moduleReach) inModule(path string, p *packages.Package) bool {
	if r.module != "stdlib" {
		return underModule(path, r.module) || (p != nil && p.Module != nil && p.Module.Path == r.module)
	}
	if (p != nil && p.Module != nil) || !isStdlibPath(path, r.modules) {
		return false
	}
	return len(r.vulnerable) == 0 || slices.Contains(r.vulnerable, path)
}

// reachesModule reports whether p, or a package it imports directly or through others, counts.
func (r *moduleReach) reachesModule(p *packages.Package) bool {
	if v, ok := r.reaches[p]; ok {
		return v
	}
	r.reaches[p] = false
	v := r.inModule(p.PkgPath, p)
	for _, imp := range p.Imports {
		if v {
			break
		}
		v = r.reachesModule(imp)
	}
	r.reaches[p] = v
	return v
}

// importGraph is a package import graph `go list -deps` resolves, unioned over every port it ran for.
type importGraph map[string][]string

// list adds imp and its dependencies, as `go list -deps` resolves them under the scan's own GOOS and
// each of the common ports, and reports whether any port listed them all without error. A left-out
// file is most often one for another of those ports, so its imports resolve there.
func (g importGraph) list(ctx context.Context, buildDir string, env []string, imp string) bool {
	ports := []string{envOr(env, "GOOS", runtime.GOOS)}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		if !slices.Contains(ports, goos) {
			ports = append(ports, goos)
		}
	}
	clean := false
	for _, goos := range ports {
		cmd := exec.CommandContext(ctx, "go", "list", "-e", "-deps", "-f", "{{.ImportPath}}{{if or .Error .DepsErrors}} !{{end}}{{range .Imports}} {{.}}{{end}}", imp)
		cmd.Dir = buildDir
		cmd.Env = append(slices.Clip(env), "GOOS="+goos)
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		port := importGraph{}
		ok := true
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			if slices.Contains(f[1:], "!") {
				ok = false
				break
			}
			port[f[0]] = f[1:]
		}
		if _, root := port[imp]; !ok || !root {
			continue
		}
		clean = true
		for p, imps := range port {
			g[p] = append(g[p], imps...)
		}
	}
	return clean
}

// reaches reports whether from, or a package it imports directly or through others, satisfies match.
func (g importGraph) reaches(from string, match func(string) bool) bool {
	seen := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if match(p) {
			return true
		}
		for _, next := range g[p] {
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	return false
}

// firstPartyLeftOut walks the main module's source tree for a package directory the load never
// listed, which is one whose every file the build left out (a tool behind a tag, a package for
// another platform), and reports whether one of its files is leftOut. It skips what the go command
// skips (testdata, vendor, and directories whose names begin with "." or "_") and nested modules.
// A directory that cannot be read counts.
func firstPartyLeftOut(root string, loadedDirs map[string]bool, leftOut func(string) bool) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			found = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !loadedDirs[filepath.Dir(path)] && leftOut(path) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// fileImports returns the import paths of the Go file at path, and whether the ignore tag
// constrains it so that no build compiles it.
func fileImports(path string) (imports []string, never bool, err error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly|parser.ParseComments)
	if err != nil {
		return nil, false, err
	}
	for _, g := range f.Comments {
		if g.Pos() >= f.Package {
			break
		}
		for _, c := range g.List {
			if !constraint.IsGoBuild(c.Text) && !constraint.IsPlusBuild(c.Text) {
				continue
			}
			if x, err := constraint.Parse(c.Text); err == nil {
				if tag, ok := x.(*constraint.TagExpr); ok && tag.Tag == "ignore" {
					never = true
				}
			}
		}
	}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return nil, false, err
		}
		imports = append(imports, p)
	}
	return imports, never, nil
}

// underModule reports whether the import path is module's own path or a package inside it.
func underModule(path, module string) bool {
	return path == module || strings.HasPrefix(path, module+"/")
}

// isStdlibPath reports whether an import path no loaded module holds belongs to the standard
// library: its first element has no dot.
func isStdlibPath(path string, modules map[string]bool) bool {
	for m := range modules {
		if underModule(path, m) {
			return false
		}
	}
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

// modGraph is the module requirement graph `go mod graph` prints, versions dropped: every
// requirement of any version of a module is an edge from it.
type modGraph map[string][]string

// readModGraph runs `go mod graph` for the module at buildDir.
func readModGraph(ctx context.Context, buildDir string, env []string) (modGraph, error) {
	cmd := exec.CommandContext(ctx, "go", "mod", "graph")
	cmd.Dir = buildDir
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go mod graph: %w", err)
	}
	g := modGraph{}
	for _, line := range strings.Split(string(out), "\n") {
		from, to, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		from, _, _ = strings.Cut(from, "@")
		to, _, _ = strings.Cut(to, "@")
		g[from] = append(g[from], to)
		if _, ok := g[to]; !ok {
			g[to] = nil
		}
	}
	return g, nil
}

// owner returns the longest module path in the graph or among the loaded modules that holds the
// import path, or "" if none does.
func (g modGraph) owner(path string, modules map[string]bool) string {
	best := ""
	consider := func(m string) {
		if len(m) > len(best) && underModule(path, m) {
			best = m
		}
	}
	for m := range g {
		consider(m)
	}
	for m := range modules {
		consider(m)
	}
	return best
}

// requires reports whether module from requires module to, directly or through other modules.
func (g modGraph) requires(from, to string) bool {
	seen := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		m := queue[0]
		queue = queue[1:]
		for _, next := range g[m] {
			if next == to {
				return true
			}
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	return false
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
