package goanalysis

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// resolvedEntrypoints is the entry-point disclosure of one build: the library set and the record
// of it entrypoints[] states.
type resolvedEntrypoints struct {
	Library *plugin.ResolvedLibraryEntrypoints `json:"library"`
	Roots   *plugin.EntryRootRecord            `json:"roots"`
}

// disclosure renders e, resolved over pkgs, as the result records it.
func (e entrypoints) disclosure(pkgs []*packages.Package, buildDir string) resolvedEntrypoints {
	lib := e.record()
	rec, _ := plugin.EntryRootRecordOf(*lib)
	rec.Inferred = inferredEntrypoints(pkgs)
	rec.Denied = e.denied(pkgs, buildDir)
	return resolvedEntrypoints{Library: lib, Roots: &rec}
}

// inferredEntrypoints is what auto nominates with nothing declared: the importable packages outside
// autoExcludedElements as libraries, and the build's main packages as mains. A main is any package
// the build compiles as main (isMain), not shippedMains: the record shows the customer every
// program the build holds, examples and tests included, to be narrowed by a "!" selector, where
// shippedMains is the program view's own judgment of which of them ship.
func inferredEntrypoints(pkgs []*packages.Package) map[string][]string {
	libs, mains := []string{}, []string{}
	for _, p := range pkgs {
		switch {
		case isMain(p):
			mains = append(mains, p.PkgPath)
		case importable(p) && !autoExcluded(p):
			libs = append(libs, p.PkgPath)
		}
	}
	slices.Sort(libs)
	slices.Sort(mains)
	libs, mains = slices.Compact(libs), slices.Compact(mains)
	return map[string][]string{plugin.EntryKindLibrary: libs, plugin.EntryKindMain: mains}
}

// denied returns the declared "!" selectors, "!" kept, that took an inferred library package out of
// the entry points: one that covers a package auto nominates, placed as resolveEntrypoints places it.
func (e entrypoints) denied(pkgs []*packages.Package, buildDir string) []string {
	if len(e.decl.Exclude) == 0 {
		return nil
	}
	base := e.decl.Base
	if base == "" {
		base = buildDir
	}
	root, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil
	}
	var out []string
	for _, x := range e.decl.Exclude {
		for _, p := range pkgs {
			if !importable(p) || autoExcluded(p) {
				continue
			}
			if dir, placed := relDir(root, p.Dir); placed && plugin.Under(dir, x) {
				out = append(out, "!"+x)
				break
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// withoutLoad records the entry points of a build no refutation made this request load. The record
// is one per tree and statement per run: the run cache holds it, so the load a path advisory
// would not otherwise make happens for the first advisory only. A load that fails records nothing
// and fails nothing: the advisory's result is what it was without the record.
func withoutLoad(ctx context.Context, res plugin.ReachabilityResult, buildDir string, entry plugin.LibraryEntrypoints, load func() (*LoadResult, error)) plugin.ReachabilityResult {
	key := append(loadCacheKey(ctx, buildDir), "entryroots", "base="+entry.Base, "statement="+entry.String())
	b, err := runCached(ctx, "entryroots", key, func() ([]byte, error) {
		loaded, err := load()
		if err != nil {
			return nil, err
		}
		return json.Marshal(resolveEntrypoints(loaded.Packages, entry, buildDir).disclosure(loaded.Packages, buildDir))
	})
	if err != nil {
		return res
	}
	var d resolvedEntrypoints
	if json.Unmarshal(b, &d) != nil || d.Library == nil {
		return res
	}
	res.LibraryEntrypoints, res.EntryRoots = d.Library, d.Roots
	return res
}
