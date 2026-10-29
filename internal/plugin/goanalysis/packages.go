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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
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

	// cgo bounds every cgo boundary in the build (cgoLimits) when cgoBounded; otherwise cgo stays a
	// run-wide reason.
	cgo        []plugin.ScopedReason
	cgoBounded bool
	// cgoUnresolved: `go env CGO_ENABLED` failed, so which variant of the build was loaded is unknown.
	cgoUnresolved bool
	// goVersion is the Go release the load ran under; buildGoVersion is the subject's toolchain when
	// the caller established it (loadForBuild), else "". buildGoFloor is the subject's binding go.mod
	// floor when the caller holds one, else "". buildRelease reads them.
	goVersion      string
	buildGoVersion string
	buildGoFloor   string
}

// releaseBound is what is established about the Go release a build compiles under: exactly release,
// or, when exact is false, release or any later one.
type releaseBound struct {
	release goRelease
	exact   bool
}

// buildRelease returns what is established about the Go release the build compiles under, or nil
// when nothing is. The load's release is the build's exactly when the subject's toolchain is known
// and names the same minor, which alone decides the goN.M build tags a build satisfies. Otherwise
// the subject's binding floor, when the caller holds one, bounds it from below. The go command on the
// analyzer's PATH establishes neither: in a dedicated scan job that is the runner's Go, not the
// build's.
func (l *LoadResult) buildRelease() *releaseBound {
	loaded, okLoaded := parseGoRelease(l.goVersion)
	build, okBuild := parseGoRelease(l.buildGoVersion)
	if okLoaded && okBuild && build.major == loaded.major && build.minor == loaded.minor {
		return &releaseBound{release: loaded, exact: true}
	}
	if floor, ok := parseGoRelease(l.buildGoFloor); ok {
		return &releaseBound{release: floor}
	}
	return nil
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
	// The build loaded is the one `go build` ships from this environment: cgo is on or off as the go
	// command resolves it here (CGO_ENABLED and CC inherited, else on when the default C compiler is
	// found), pinned so every load reads that one variant. The files the other variant compiles are
	// the dropped limit below.
	pinned, cgoErr := cgoPinned(ctx, buildDir, cfg.Env)
	if cgoErr == nil {
		cfg.Env = pinned
	}
	// The toolchain is the one the go command resolves here from GOTOOLCHAIN and the go.mod go and
	// toolchain lines, pinned so every load runs under that one release. It is not the build's: a
	// caller that knows the subject's toolchain sets buildGoVersion.
	goVersion := goEnvVersion(ctx, buildDir, cfg.Env)
	if r, ok := parseGoRelease(goVersion); ok {
		cfg.Env = append(cfg.Env, "GOTOOLCHAIN="+r.toolchain())
	} else {
		goVersion = ""
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
	cgo, dropped, bounded := cgoLimits(pkgs, cfg.Env)
	if dropped && !bounded {
		reasons = append(reasons, plugin.PartialReasonCgo)
	}
	if cgoErr != nil {
		reasons = append(reasons, plugin.PartialReasonCgoUnresolved)
	}
	if len(reasons) > 0 {
		part = plugin.Partial(reasons...)
	}
	if !bounded {
		cgo = nil
	}
	if dropped && bounded {
		part.Complete = false
		part.Scoped = cgo
	}

	return &LoadResult{
		Packages: pkgs, Partiality: part, cgo: cgo, cgoBounded: bounded, cgoUnresolved: cgoErr != nil,
		goVersion: goVersion,
	}, nil
}

type buildEnvironKey struct{}

// WithBuildEnviron returns ctx carrying env as the environment the build runs in: the process's own
// environment before the analyzer changed it (it forces GOWORK=off, which the build does not).
func WithBuildEnviron(ctx context.Context, env []string) context.Context {
	return context.WithValue(ctx, buildEnvironKey{}, env)
}

// BuildEnviron returns the build's environment ctx carries, or the process's own when it carries none.
func BuildEnviron(ctx context.Context) []string {
	if env, ok := ctx.Value(buildEnvironKey{}).([]string); ok {
		return env
	}
	return os.Environ()
}

// buildToolchain is the Go release the analyzer's go command resolves for buildDir under the build's
// environment (BuildEnviron), from GOTOOLCHAIN, the go.mod go and toolchain lines and any go.work. It
// is an ambient observation, not the release the build compiles under; see buildRelease. "" when
// unknown.
func buildToolchain(ctx context.Context, buildDir string) string {
	return goEnvVersion(ctx, buildDir, BuildEnviron(ctx))
}

// cgoPinned returns env with CGO_ENABLED set to the value `go env CGO_ENABLED` resolves for dir
// under env, or an error when the go command does not resolve it to 0 or 1.
func cgoPinned(ctx context.Context, dir string, env []string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "go", "env", "CGO_ENABLED")
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go env CGO_ENABLED: %w", err)
	}
	v := strings.TrimSpace(string(out))
	if v != "0" && v != "1" {
		return nil, fmt.Errorf("go env CGO_ENABLED: %q", v)
	}
	return append(slices.Clip(env), "CGO_ENABLED="+v), nil
}

// cgoLimits bounds what the cgo boundaries in the build can hide from the analysis, as one
// scoped limit per module holding cgo code. dropped reports a cgo file of a non-standard-library
// package that the build left out because cgo is disabled (cgoFilesDropped). bounded is false when
// no bound holds, and cgo then stays a run-wide limit.
//
// Two bounds, by whether C can call back into Go:
//
//   - It cannot (no //export, no SWIG, no prebuilt object, no dropped file): C code reaches only C
//     code, which lives in the cgo modules themselves. The targets are those modules.
//   - It can: an exported function, or a dropped Go file, is Go code no analysis root reaches, and
//     it may call any function value it is handed, first-party ones included, which may call
//     anything. The targets are every module in the build plus first-party code, plus the modules
//     of the dropped files' imports. A module outside the build has no code in the binary, so it is
//     the only thing such a limit can exclude. A dropped file importing a package the build did not
//     load leaves its module unknown, and no bound holds.
//
// The standard library's own cgo (the net resolver, os/user lookups, plugin's dlopen) that C cannot
// call back from holds no cgo module: its C calls only the C library, its Go side is in the graph,
// and an advisory on the standard library names Go symbols. Whether plugin.Open is reached is
// declared by the call graph, not here: as plugin_load (runTimeCalls), whether it is reached
// directly or reflectively.
//
// runtime/cgo itself is not a cgo package here: every cgo package imports it.
func cgoLimits(pkgs []*packages.Package, env []string) (scoped []plugin.ScopedReason, dropped, bounded bool) {
	tags := goflagsTags(env)
	cgoMods := map[string]string{} // module PURL -> one cgo package path in it
	every := map[string]bool{"": true}
	callbacks, unreadable := false, false
	var droppedImports []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		every[modulePURL(p)] = true
		if p.PkgPath == "runtime/cgo" {
			return
		}
		_, compiled := p.Imports["runtime/cgo"]
		files := cgoFilesDropped(p, tags)
		if !compiled && len(files) == 0 {
			return
		}
		callsBack := compiled && (exportsToC(p.GoFiles) || hasForeignObjects(p.OtherFiles))
		if p.Module == nil && isStdlibPath(p.PkgPath, nil) && !callsBack {
			return
		}
		if mod := modulePURL(p); cgoMods[mod] == "" || p.PkgPath < cgoMods[mod] {
			cgoMods[mod] = p.PkgPath
		}
		if len(files) > 0 {
			dropped, callbacks = true, true
			for _, f := range files {
				_, imps, _, err := fileImports(f)
				unreadable = unreadable || err != nil
				droppedImports = append(droppedImports, imps...)
			}
		}
		callbacks = callbacks || callsBack
	})
	if len(cgoMods) == 0 {
		return nil, false, true
	}
	if unreadable {
		return nil, dropped, false
	}

	targets := map[string]bool{}
	for mod := range cgoMods {
		targets[mod] = true
	}
	if callbacks {
		loaded := map[string]bool{}
		packages.Visit(pkgs, nil, func(p *packages.Package) { loaded[p.PkgPath] = true })
		for mod := range every {
			targets[mod] = true
		}
		targets[stdlibPURL] = true
		for _, imp := range droppedImports {
			switch {
			case imp == "C" || loaded[imp]:
			case isStdlibPath(imp, nil):
				targets[stdlibPURL] = true
			default:
				return nil, dropped, false
			}
		}
	}
	list := sortedKeys(targets)
	for _, mod := range sortedKeys(mapKeys(cgoMods)) {
		scoped = append(scoped, plugin.ScopedReason{
			Reason:  plugin.PartialReasonCgo,
			Package: mod,
			Path:    cgoMods[mod],
			Targets: list,
		})
	}
	return scoped, dropped, true
}

const stdlibPURL = "pkg:golang/stdlib"

// modulePURL names p's module as a scoped limit does: "" for the module under analysis, the
// standard library as one package, any other module by its path.
func modulePURL(p *packages.Package) string {
	switch {
	case p.Module == nil:
		return stdlibPURL
	case p.Module.Main:
		return ""
	}
	return "pkg:golang/" + p.Module.Path
}

// cgoFilesDropped lists the cgo files of a non-standard-library package that the build left out
// because cgo is disabled (CGO_ENABLED=0, or no C compiler). Such a file is in no package's syntax,
// so neither the call graph nor govulncheck sees the calls it makes, and runtime/cgo never enters
// the program to trip the cgo detector. A file the build would leave out with cgo enabled too
// (another GOOS, a build tag) is not counted; a file that cannot be read is, since it may be neither.
// The files are matched under tags, the build tags GOFLAGS sets for the load.
//
// The standard library's own cgo variants (net, os/user) are not checked: their pure-Go
// fallbacks are what the build compiles, and the analysis reads those.
func cgoFilesDropped(p *packages.Package, tags []string) []string {
	if p.Module == nil {
		return nil
	}
	ctx := build.Default
	ctx.CgoEnabled = true
	ctx.BuildTags = tags
	var files []string
	for _, path := range p.IgnoredFiles {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		if importsC(path) {
			if ok, err := ctx.MatchFile(filepath.Dir(path), filepath.Base(path)); err != nil || ok {
				files = append(files, path)
			}
		}
	}
	return files
}

// exportsToC reports whether any of the Go files exports a function to C (a //export directive).
// An unreadable file counts: it may.
func exportsToC(files []string) bool {
	for _, path := range files {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
		if err != nil {
			return true
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.HasPrefix(c.Text, "//export ") {
					return true
				}
			}
		}
	}
	return false
}

// hasForeignObjects reports whether a package carries code the cgo boundary does not describe: a
// SWIG interface, whose generated wrappers call back into Go, or a prebuilt object linked as is.
func hasForeignObjects(files []string) bool {
	for _, f := range files {
		switch filepath.Ext(f) {
		case ".swig", ".swigcxx", ".syso":
			return true
		}
	}
	return false
}

func mapKeys(m map[string]string) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
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

// leftOutCallers reports whether a non-test Go file the build left out of a package (one for another
// GOOS or GOARCH, or behind a build tag) may call into module. No package's syntax holds such a
// file, so govulncheck traced no call from it, yet a build for that platform or with that tag
// compiles it.
//
// A file may call into a module when it imports, directly or through other packages, one of the
// module's packages that count: the advisory's vulnerable packages (vulnerable), or every package of
// the module when that is empty. A loaded import is followed through the load; the files the build
// left out of it are left-out files in their own right. An import the build did not load is followed
// through the imports of every Go file in its directory, whatever their build constraints, so through
// any build configuration that compiles it (sourceImports). An unloaded import counts outright when
// its directory or one of its files cannot be read, when the module graph cannot be read, or when no
// module in it holds the import; one from a module that neither is nor requires module does not
// count, nor does a standard-library one, where a path with no dot in its first element is the
// standard library's only when no module in the graph holds it. A file that cannot be read counts. A
// file left out of a loaded package that reaches a package that counts through the load counts
// whatever it imports, unless its package clause names another package. A file constrained by the
// ignore tag is never built and does not count, nor, when release bounds the Go release the build
// compiles under, is a file whose goN.M build tags alone exclude it from every build under that
// bound (releaseBound.excludes); the files of an unloaded import are read the same way.
//
// When module is the standard library, the packages that count are its vulnerable ones, or every
// standard-library package when vulnerable is empty. Every unloaded import is followed, the standard
// library's own included, and the files the build left out of the standard library's loaded packages
// are left-out files too: another platform's file may call what the scan's own platform never
// reaches. The golang.org/x packages the standard library imports resolve to its vendored copies.
// Outside a standard-library refutation, the standard library's own files are not checked: it
// imports no module.
func leftOutCallers(ctx context.Context, pkgs []*packages.Package, module string, vulnerable []string, release *releaseBound, buildDir string, env []string) bool {
	reach := newModuleReach(pkgs, module, vulnerable)
	stdlib := module == "stdlib"
	var graph modGraph
	var graphErr error
	graphRead := false
	src := sourceImports{}
	built := func(expr constraint.Expr) bool {
		return !ignored(expr) && (release == nil || !release.excludes(expr))
	}

	// classify reports whether the import imp counts outright and, when it does not, whether it is a
	// package the build did not load whose own imports decide.
	classify := func(imp string) (counts, follow bool) {
		if p, ok := reach.loaded[imp]; ok {
			return reach.reachesModule(p), false
		}
		if reach.inModule(imp, nil) {
			return true, false
		}
		if imp == "C" {
			return false, false
		}
		if !stdlib {
			if !graphRead {
				graph, graphErr = readModGraph(ctx, buildDir, env)
				graphRead = true
			}
			if graphErr != nil {
				return true, false
			}
		}
		if !stdlib && isStdlibPath(imp, reach.modules) && graph.owner(imp, reach.modules) == "" {
			return false, false
		}
		if !stdlib {
			owner := graph.owner(imp, reach.modules)
			if owner == "" {
				return true, false
			}
			if !underModule(module, owner) && !graph.requires(owner, module) {
				return false, false
			}
		}
		return false, true
	}
	memo := map[string]bool{}
	mayCall := func(imp string) bool {
		if v, ok := memo[imp]; ok {
			return v
		}
		v := false
		seen := map[string]bool{imp: true}
		for frontier := []string{imp}; len(frontier) > 0 && !v; {
			var follow []string
			for _, p := range frontier {
				counts, f := classify(p)
				if counts {
					v = true
					break
				}
				if f {
					follow = append(follow, p)
				}
			}
			if v {
				break
			}
			src.read(ctx, buildDir, env, follow, built)
			frontier = nil
			for _, p := range follow {
				imports, ok := src[p]
				if !ok {
					v = true
					break
				}
				for _, next := range imports {
					if !seen[next] {
						seen[next] = true
						frontier = append(frontier, next)
					}
				}
			}
		}
		memo[imp] = v
		return v
	}

	// leftOutOf reports whether the non-test Go file at path may call into module. A file of package
	// own, when own reaches a package that counts, may whatever it imports: it can call any of that
	// package's functions, and govulncheck traced only the ones the build calls. A file whose package
	// clause names another package never compiles into own.
	leftOutOf := func(path string, own string, std bool) bool {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return false
		}
		name, imports, expr, err := fileImports(path)
		if err != nil {
			return true
		}
		if !built(expr) {
			return false
		}
		if std {
			// The standard library resolves the golang.org/x packages it imports to its own vendor copies.
			for i, imp := range imports {
				if !isStdlibPath(imp, nil) {
					imports[i] = "vendor/" + imp
				}
			}
		}
		return (own != "" && name == own) || slices.ContainsFunc(imports, mayCall)
	}
	leftOut := func(path string) bool { return leftOutOf(path, "", false) }

	found := false
	loadedDirs := map[string]bool{}
	mainDir := ""
	packages.Visit(pkgs, func(p *packages.Package) bool {
		if found {
			return false
		}
		if p.Module == nil {
			if stdlib && isStdlibPath(p.PkgPath, reach.modules) {
				own := ""
				if reach.reachesModule(p) {
					own = p.Name
				}
				found = slices.ContainsFunc(p.IgnoredFiles, func(f string) bool { return leftOutOf(f, own, true) })
			}
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
		own := ""
		if reach.reachesModule(p) {
			own = p.Name
		}
		found = slices.ContainsFunc(p.IgnoredFiles, func(f string) bool { return leftOutOf(f, own, false) })
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
// refuted module's packages that count: its vulnerable packages (vulnerable), or every package of the
// module when that is empty.
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
		if !underModule(path, r.module) && (p == nil || p.Module == nil || p.Module.Path != r.module) {
			return false
		}
		return len(r.vulnerable) == 0 || slices.Contains(r.vulnerable, path)
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

// sourceImports holds, for each package the build did not load, the imports of every non-test Go
// file in its directory that some build could compile, unioned. A package whose directory, or one of
// whose files, could not be read is absent.
type sourceImports map[string][]string

// read adds the packages of paths not yet read. `go list` finds each one's directory the way the
// build would (the selected module version, a replacement, the vendor directory) without building
// it, so a package whose files the scan's own configuration excludes is still found. built reports
// whether a file with that build constraint can compile at all.
func (s sourceImports) read(ctx context.Context, buildDir string, env []string, paths []string, built func(constraint.Expr) bool) {
	var todo []string
	for _, p := range paths {
		if _, ok := s[p]; !ok && !strings.HasPrefix(p, "-") {
			todo = append(todo, p)
		}
	}
	if len(todo) == 0 {
		return
	}
	cmd := exec.CommandContext(ctx, "go", append([]string{"list", "-e", "-f", "{{.ImportPath}}\t{{.Standard}}\t{{.Dir}}"}, todo...)...)
	cmd.Dir = buildDir
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return
	}
	dirs := map[string]string{}
	standard := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.SplitN(line, "\t", 3); len(f) == 3 && f[2] != "" {
			dirs[f[0]] = f[2]
			standard[f[0]] = f[1] == "true"
		}
	}
	for _, p := range todo {
		if dir, ok := dirs[p]; ok {
			if imports, ok := dirImports(dir, built); ok {
				if standard[p] {
					// The standard library resolves the golang.org/x packages it imports to its own vendor copies.
					for i, imp := range imports {
						if !isStdlibPath(imp, nil) {
							imports[i] = "vendor/" + imp
						}
					}
				}
				s[p] = imports
			}
		}
	}
}

// dirImports returns the imports of every non-test Go file in dir that built admits, unioned, and
// whether dir and each of those files could be read.
func dirImports(dir string, built func(constraint.Expr) bool) ([]string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	imports := []string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		_, imps, expr, err := fileImports(filepath.Join(dir, name))
		if err != nil {
			return nil, false
		}
		if built(expr) {
			imports = append(imports, imps...)
		}
	}
	slices.Sort(imports)
	return slices.Compact(imports), true
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

// fileImports returns the package name, import paths and build constraint of the Go file at path.
// The constraint is read as go/build reads it (see fileConstraint).
func fileImports(path string) (name string, imports []string, expr constraint.Expr, err error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return "", nil, nil, err
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
	if err != nil {
		return "", nil, nil, err
	}
	if expr, err = fileConstraint(src); err != nil {
		return "", nil, nil, err
	}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return "", nil, nil, err
		}
		imports = append(imports, p)
	}
	return f.Name.Name, imports, expr, nil
}

// fileConstraint returns the build constraint go/build applies to a Go file with content src:
// its //go:build line anywhere in the leading run of comments and blank lines, else the
// plus-build lines of that run that precede its last blank line (which keeps a package doc comment
// out), together; nil when there is none. A file go/build rejects (two //go:build lines, or one that
// does not parse) is an error.
func fileConstraint(src []byte) (constraint.Expr, error) {
	var goBuild string
	var plusBuild []string
	var pending []string // plus-build lines since the last blank line
	// headed: past the first line that is not a // comment, so no later blank line ends the header.
	inSlashStar, headed := false, false
	for p := src; len(p) > 0; {
		line := p
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line, p = line[:i], p[i+1:]
		} else {
			p = nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 && !headed {
			plusBuild, pending = append(plusBuild, pending...), nil
			continue
		}
		headed = headed || !bytes.HasPrefix(line, []byte("//"))
		text := string(line)
		if !inSlashStar && constraint.IsGoBuild(text) {
			if goBuild != "" {
				return nil, errors.New("multiple //go:build comments")
			}
			goBuild = text
		}
		if !headed && constraint.IsPlusBuild(text) {
			pending = append(pending, text)
		}
		ended := false
		for len(line) > 0 && !ended {
			switch {
			case inSlashStar:
				i := bytes.Index(line, []byte("*/"))
				if i < 0 {
					line = nil
					continue
				}
				inSlashStar, line = false, bytes.TrimSpace(line[i+2:])
			case bytes.HasPrefix(line, []byte("//")):
				line = nil
			case bytes.HasPrefix(line, []byte("/*")):
				inSlashStar, line = true, bytes.TrimSpace(line[2:])
			default:
				ended = true
			}
		}
		if ended {
			break
		}
	}
	if goBuild != "" {
		return constraint.Parse(goBuild)
	}
	var expr constraint.Expr
	for _, text := range plusBuild {
		x, err := constraint.Parse(text)
		switch {
		case err != nil:
		case expr == nil:
			expr = x
		default:
			expr = &constraint.AndExpr{X: expr, Y: x}
		}
	}
	return expr, nil
}

// ignored reports whether the build constraint x is the ignore tag, which no build sets.
func ignored(x constraint.Expr) bool {
	tag, ok := x.(*constraint.TagExpr)
	return ok && tag.Tag == "ignore"
}

// maxFreeTags bounds the tags releaseExcluded enumerates; a constraint with more is not judged.
const maxFreeTags = 16

// releaseExcluded reports whether the build constraint x excludes a file only through its goN.M
// release tags: some assignment of its tags satisfies x, but none does once every release tag takes
// the value a build under release r gives it. Every other tag (GOOS, GOARCH, cgo, custom tags)
// ranges freely, so a file that some platform or tag of a build under r selects is not excluded.
// A tag spelled otherwise than a release tag the go command sets ("go1.05") is not one.
func releaseExcluded(x constraint.Expr, r goRelease) bool {
	if x == nil {
		return false
	}
	var tags []string
	release := map[string]bool{}
	seen := map[string]bool{}
	var walk func(constraint.Expr)
	walk = func(x constraint.Expr) {
		switch x := x.(type) {
		case *constraint.TagExpr:
			if seen[x.Tag] {
				return
			}
			seen[x.Tag] = true
			if minor, ok := releaseTagMinor(x.Tag); ok {
				release[x.Tag] = r.major > 1 || minor <= r.minor
			} else {
				tags = append(tags, x.Tag)
			}
		case *constraint.NotExpr:
			walk(x.X)
		case *constraint.AndExpr:
			walk(x.X)
			walk(x.Y)
		case *constraint.OrExpr:
			walk(x.X)
			walk(x.Y)
		}
	}
	walk(x)
	if len(release) == 0 || len(seen) > maxFreeTags {
		return false
	}
	// satisfiable reports whether some assignment of free satisfies x, with fixed for the rest.
	satisfiable := func(free []string, fixed map[string]bool) bool {
		for mask := 0; mask < 1<<len(free); mask++ {
			on := map[string]bool{}
			for i, tag := range free {
				on[tag] = mask&(1<<i) != 0
			}
			if x.Eval(func(tag string) bool {
				if v, ok := fixed[tag]; ok {
					return v
				}
				return on[tag]
			}) {
				return true
			}
		}
		return false
	}
	all := slices.Sorted(maps.Keys(seen))
	return satisfiable(all, nil) && !satisfiable(tags, release)
}

// excludes reports whether the build constraint x excludes a file from every build under b. Under an
// exact release that is releaseExcluded at it. Under a floor 1.f it is releaseExcluded at every
// release minor m >= f, judged at f and at each minor above f that x's release tags name. Under m,
// a release tag go1.n holds exactly when n <= m, so the values of x's release tags, and with them
// releaseExcluded, change with m only where m reaches a minor x names: every m in [f, inf) gives the
// values of the largest judged minor at or below it, and above the highest minor x names every one
// of its release tags holds for good. A floor with another major is not judged.
func (b releaseBound) excludes(x constraint.Expr) bool {
	if b.exact {
		return releaseExcluded(x, b.release)
	}
	if b.release.major != 1 {
		return false
	}
	for _, m := range releaseMinorsFrom(x, b.release.minor) {
		if !releaseExcluded(x, goRelease{major: 1, minor: m}) {
			return false
		}
	}
	return true
}

// releaseMinorsFrom returns floor and every release minor above it that x's release tags name,
// ascending and without repeats.
func releaseMinorsFrom(x constraint.Expr, floor int) []int {
	minors := []int{floor}
	var walk func(constraint.Expr)
	walk = func(x constraint.Expr) {
		switch x := x.(type) {
		case *constraint.TagExpr:
			if n, ok := releaseTagMinor(x.Tag); ok && n > floor {
				minors = append(minors, n)
			}
		case *constraint.NotExpr:
			walk(x.X)
		case *constraint.AndExpr:
			walk(x.X)
			walk(x.Y)
		case *constraint.OrExpr:
			walk(x.X)
			walk(x.Y)
		}
	}
	walk(x)
	slices.Sort(minors)
	return slices.Compact(minors)
}

// releaseTagMinor returns N for a release tag "go1.N" as the go command spells it (N >= 1, no
// leading zeros or sign).
func releaseTagMinor(tag string) (int, bool) {
	rest, ok := strings.CutPrefix(tag, "go1.")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 1 || strconv.Itoa(n) != rest {
		return 0, false
	}
	return n, true
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
	index, err := resolutionIndex(ctx, req.BuildDir)
	if err != nil {
		return plugin.SymbolResolutionResult{}, err
	}

	pkgFilter := packageFromPURL(req.PURL)
	var search *plugin.ModuleSearch
	wanted := make(map[string]bool, len(req.AdvisorySymbols))
	for _, s := range req.AdvisorySymbols {
		wanted[s] = true
	}

	// The index holds the build's own packages only, so the PURL package filter applies when the
	// advisory names one of them. A FIRST-PARTY advisory may carry a synthetic PURL
	// (pkg:golang/<app>) that is NOT a loaded package path (the repro's module path is its own,
	// e.g. tegron.corpus/<repro>), so an exact-path filter would drop every candidate. When the
	// filter matches no loaded package and neither the standard library nor a dependency module
	// holds the path, drop it and resolve the advisory symbols by name across the program —
	// AdvisorySymbols are still the GIVEN ground truth (inv.7); only the package SCOPE is relaxed,
	// never the symbol identity.
	if pkgFilter != "" {
		present := false
		for _, sym := range index.Symbols {
			if sym.Package == pkgFilter {
				present = true
				break
			}
		}
		if !present {
			// The standard library or a dependency module holds the advisory's package: its code is
			// not in the index, and a first-party symbol that shares a name with an advisory symbol
			// is not the advisory's.
			if isToolchainPackage(pkgFilter) || dependencyHolds(ctx, req.BuildDir, pkgFilter) {
				return plugin.SymbolResolutionResult{Partiality: index.Partiality}, nil
			}
			// No loaded package is the advisory's: if no module in the build holds it either,
			// search every module's source for the symbols, which is what can show the
			// advisory's code is not in the build under another path.
			search = searchBuildModules(ctx, req.BuildDir, pkgFilter, req.AdvisorySymbols)
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

	return plugin.SymbolResolutionResult{Partiality: index.Partiality, Resolved: resolved, ModuleSearch: search}, nil
}

// resolutionIndex returns the symbol index ResolveDependencySymbols filters, built once per tree per
// scan through the run cache: the index depends only on the build, while every advisory resolves
// against it. The program load reads the process environment, so that is part of the key.
func resolutionIndex(ctx context.Context, buildDir string) (plugin.SymbolIndexResult, error) {
	b, err := runCached(ctx, "symbolindex", append([]string{buildDir}, os.Environ()...), func() ([]byte, error) {
		index, err := IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: buildDir})
		if err != nil {
			return nil, err
		}
		return json.Marshal(index)
	})
	if err != nil {
		return plugin.SymbolIndexResult{}, err
	}
	var index plugin.SymbolIndexResult
	if err := json.Unmarshal(b, &index); err != nil {
		return plugin.SymbolIndexResult{}, fmt.Errorf("decode cached symbol index: %w", err)
	}
	return index, nil
}

// isToolchainPackage reports whether a PURL package names the Go distribution rather than a
// module: "stdlib", "toolchain" (govulncheck's module for cmd/go and its tools), or a cmd/
// package. None is held by any listed module, so none is found by a module search.
func isToolchainPackage(pkg string) bool {
	return strings.EqualFold(pkg, packageFromPURL(stdlibPURL)) || strings.EqualFold(pkg, "toolchain") ||
		pkg == "cmd" || strings.HasPrefix(pkg, "cmd/")
}

// packageFromPURL extracts the import path from a Go PURL of the form
// pkg:golang/<import-path>[@version][?qualifiers][#subpath]. An empty or non-golang PURL yields ""
// (no package filter), so resolution falls back to matching by symbol name alone. The type is
// matched case-insensitively and the path ends at the first '@', '?' or '#', as pipeline's
// isGoStdlibPURL reads it (this package cannot import pipeline).
func packageFromPURL(purl string) string {
	const prefix = "pkg:golang/"
	if len(purl) < len(prefix) || !strings.EqualFold(purl[:len(prefix)], prefix) {
		return ""
	}
	path := purl[len(prefix):]
	for _, sep := range []byte{'#', '?', '@'} {
		if i := strings.IndexByte(path, sep); i >= 0 {
			path = path[:i]
		}
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
