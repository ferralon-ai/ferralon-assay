package goanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// replacedResolution resolves the advisory symbols of package pkgPath in the code the build compiles
// for it when a replace directive sends pkgPath's module to another module or a local directory: the
// build compiles that code under pkgPath, so its declarations are the ones a call reaches. It reports
// false, and the caller keeps its empty answer, when no such replace holds pkgPath, or the build does
// not compile pkgPath, or compiles it with errors: an absent or broken package says nothing about what
// the replacement defines.
//
// A symbol resolves only to a function, or a method declared on the named type, of pkgPath itself.
// One that pkgPath does not define is unresolved, and the result says so. One qualified by a package
// the build's resolved package set does not hold (outsideBuild) is listed in OutsideBuild instead,
// when the load is complete: an incomplete one may have left that package out.
func replacedResolution(ctx context.Context, buildDir, pkgPath string, symbols []string) (plugin.SymbolResolutionResult, bool) {
	mods, err := listModules(ctx, buildDir)
	if err != nil || !replaceHolds(mods, pkgPath) {
		return plugin.SymbolResolutionResult{}, false
	}
	sorted := slices.Clone(symbols)
	sort.Strings(sorted)
	b, err := runCached(ctx, "forkresolve", buildKey(ctx, buildDir, append([]string{pkgPath}, sorted...)...), func() ([]byte, error) {
		res, ok, err := resolveReplaced(ctx, buildDir, pkgPath, symbols, mods)
		if err != nil {
			return nil, err
		}
		if !ok {
			return []byte("null"), nil
		}
		return json.Marshal(res)
	})
	if err != nil || string(b) == "null" {
		return plugin.SymbolResolutionResult{}, false
	}
	var res plugin.SymbolResolutionResult
	if err := json.Unmarshal(b, &res); err != nil {
		return plugin.SymbolResolutionResult{}, false
	}
	return res, true
}

// replaceHolds reports whether the module of the build list holding import path p with the longest
// path is replaced by a module of another path or by a directory.
func replaceHolds(mods []listedModule, p string) bool {
	var holder *listedModule
	for i, m := range mods {
		if pathHolds(m.Path, p) && (holder == nil || len(m.Path) > len(holder.Path)) {
			holder = &mods[i]
		}
	}
	return holder != nil && !holder.Main && holder.Replace != nil && holder.Replace.Path != holder.Path
}

func resolveReplaced(ctx context.Context, buildDir, pkgPath string, symbols []string, mods []listedModule) (plugin.SymbolResolutionResult, bool, error) {
	loaded, err := LoadProgram(ctx, buildDir)
	if err != nil {
		return plugin.SymbolResolutionResult{}, false, err
	}
	compiled := map[string]*packages.Package{}
	packages.Visit(loaded.Packages, nil, func(p *packages.Package) {
		compiled[p.PkgPath] = p
	})
	target := compiled[pkgPath]
	if target == nil || target.Types == nil || len(target.Errors) > 0 || len(target.TypeErrors) > 0 || target.IllTyped {
		return plugin.SymbolResolutionResult{}, false, nil
	}
	held, err := replaceSources(buildDir, goWork(ctx), mods)
	if err != nil {
		return plugin.SymbolResolutionResult{}, false, nil
	}
	res := plugin.SymbolResolutionResult{Partiality: loaded.Partiality, Origins: map[string]string{}, Matched: map[string][]string{}}
	unresolved := false
	for _, sym := range symbols {
		if obj := lookupInPackage(target.Types, inPackageName(sym, pkgPath)); obj != nil {
			scip := scipFromPackage(target, obj)
			res.Resolved = append(res.Resolved, plugin.Symbol{SCIP: scip, DisplayName: displayName(obj), Package: pkgPath})
			res.Origins[scip] = "pkg:golang/" + pkgPath
			res.Matched[sym] = append(res.Matched[sym], scip)
			continue
		}
		if loaded.Partiality.Complete && outsideBuild(sym, compiled, held) {
			res.OutsideBuild = append(res.OutsideBuild, sym)
			continue
		}
		unresolved = true
	}
	if unresolved {
		res.Partiality = withReason(res.Partiality, plugin.PartialReasonAdvisorySymbolUnresolved)
	}
	return res, true, nil
}

// inPackageName returns the part of advisory symbol sym that names a declaration of package pkgPath:
// sym without its "pkgPath." qualifier, or sym itself when it carries no import path. It returns ""
// when sym is qualified by another package.
func inPackageName(sym, pkgPath string) string {
	if !strings.Contains(sym, "/") {
		return sym
	}
	for _, q := range qualifiers(sym) {
		if q.pkg == pkgPath {
			return q.name
		}
	}
	return ""
}

// lookupInPackage returns the function "F", or the method "T.M" declared on named type T, of pkg; nil
// for any other name. A method T gets by embedding is not T's own declaration, and not returned.
func lookupInPackage(pkg *types.Package, name string) types.Object {
	if name == "" {
		return nil
	}
	typ, method, isMethod := strings.Cut(name, ".")
	if !isMethod {
		fn, _ := pkg.Scope().Lookup(name).(*types.Func)
		if fn == nil {
			return nil
		}
		return fn
	}
	if strings.Contains(method, ".") {
		return nil
	}
	tn, _ := pkg.Scope().Lookup(typ).(*types.TypeName)
	if tn == nil {
		return nil
	}
	named, _ := tn.Type().(*types.Named)
	if named == nil {
		return nil
	}
	for i := 0; i < named.NumMethods(); i++ {
		if m := named.Method(i); m.Name() == method {
			return m
		}
	}
	return nil
}

// qualified is one reading of a package-qualified symbol: the import path and the name inside it.
type qualified struct{ pkg, name string }

// qualifiers returns every reading of sym as "<import path>.<name>": the import path ends at a '.'
// after sym's last '/', since a path element may itself hold dots (gopkg.in/yaml.v2). A symbol with no
// '/' carries no import path and has none.
func qualifiers(sym string) []qualified {
	slash := strings.LastIndexByte(sym, '/')
	if slash < 0 {
		return nil
	}
	var out []qualified
	for i := slash + 1; i < len(sym); i++ {
		if sym[i] == '.' && i+1 < len(sym) {
			out = append(out, qualified{pkg: sym[:i], name: sym[i+1:]})
		}
	}
	return out
}

// outsideBuild reports whether the package qualifying advisory symbol sym is absent from the build's
// resolved package set, under every reading of its qualifier: the build compiles no package of that
// path, and no replace directive's source holds it (replaceSources). A symbol with no import path is
// never outside the build.
func outsideBuild(sym string, compiled map[string]*packages.Package, held func(string) bool) bool {
	qs := qualifiers(sym)
	if len(qs) == 0 {
		return false
	}
	for _, q := range qs {
		for p := range compiled {
			if strings.EqualFold(p, q.pkg) {
				return false
			}
		}
		if held(q.pkg) {
			return false
		}
	}
	return true
}

// replaceSources returns whether an import path is the source side of a replace directive of the
// build: a replaced module of the build list whose path is the import path, or holds it as one of its
// own package paths, or holds it under a major-version suffix that is a directory of the
// replacement's tree; or a replace directive of the build's go.mod or go.work, on a
// module the build list does not hold, whose source path holds it. A replacement whose tree cannot be
// read holds every import path below its module path.
func replaceSources(buildDir, goWork string, mods []listedModule) (func(string) bool, error) {
	listed := map[string]bool{}
	for _, m := range mods {
		listed[m.Path] = true
	}
	var unlisted []string
	files := []string{filepath.Join(buildDir, "go.mod")}
	if goWork != "" && goWork != "off" {
		files = append(files, goWork)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var olds []string
		if strings.HasSuffix(f, "go.mod") {
			mf, err := modfile.Parse(f, data, nil)
			if err != nil {
				return nil, err
			}
			for _, r := range mf.Replace {
				olds = append(olds, r.Old.Path)
			}
		} else {
			wf, err := modfile.ParseWork(f, data, nil)
			if err != nil {
				return nil, err
			}
			for _, r := range wf.Replace {
				olds = append(olds, r.Old.Path)
			}
		}
		for _, old := range olds {
			if !listed[old] {
				unlisted = append(unlisted, old)
			}
		}
	}
	return func(p string) bool {
		for _, old := range unlisted {
			if pathHolds(old, p) {
				return true
			}
		}
		for _, m := range mods {
			if m.Replace == nil || !pathHolds(m.Path, p) {
				continue
			}
			rel := strings.TrimPrefix(p[len(m.Path):], "/")
			if rel == "" {
				return true
			}
			// A package path of the replaced module itself that the replacement lacks is code the fork
			// renamed or removed, not code outside the build. Only a major-version suffix (m.Path/vN)
			// of a module path carrying none names another module, and only when the replacement's
			// tree has no vN directory, which would make every path below it the module's own. The
			// element is read up to its first dot as well, since qualifiers also reads "vN.T" as a
			// path element.
			if _, major, _ := module.SplitPathVersion(m.Path); major != "" {
				return true
			}
			first, _, _ := strings.Cut(rel, "/")
			first, _, _ = strings.Cut(first, ".")
			if _, major, ok := module.SplitPathVersion(m.Path + "/" + first); !ok || major == "" {
				return true
			}
			dir := m.Replace.Dir
			if dir == "" {
				dir = m.Dir
			}
			if dir == "" {
				return true
			}
			if _, err := os.Stat(filepath.Join(dir, first)); !errors.Is(err, os.ErrNotExist) {
				return true
			}
		}
		return false
	}, nil
}
