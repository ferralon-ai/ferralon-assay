package goanalysis

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// disclosure renders e, resolved over pkgs, as the record entrypoints[] states.
func (e entrypoints) disclosure(pkgs []*packages.Package, buildDir string) *plugin.EntryRootRecord {
	rec, _ := plugin.EntryRootRecordOf(*e.record())
	rec.Inferred = inferredEntrypoints(pkgs)
	if len(e.mains) > 0 {
		// Read as an application, the mains are the entry points: the record names the ones the
		// reading rests on.
		rec.Effective[plugin.EntryKindMain] = pkgPaths(e.mains)
	}
	rec.Denied = e.denied(pkgs, buildDir)
	return &rec
}

// inferredEntrypoints is what auto nominates with nothing declared: the importable packages outside
// autoExcludedElements as libraries, and the build's main packages as mains. A main is any package
// the build compiles as main (isMain), not shippedMains: the record lists every program the
// build holds, examples and tests included, for information, and every one is an entry point, where
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

// withoutLoad records the entrypoints[] record of a build no refutation made this request load. The
// record is one per tree and statement per run: the run cache holds it, so the load a path advisory
// would not otherwise make happens for the first advisory only. A load that fails records nothing
// and fails nothing: the advisory's result is what it was without the record. It sets EntryRoots
// alone: the top-level library_entrypoints stays what a refutation judged, as the stored report's
// restated check reads it.
func withoutLoad(ctx context.Context, res plugin.ReachabilityResult, buildDir string, entry plugin.LibraryEntrypoints, load func() (*LoadResult, error)) plugin.ReachabilityResult {
	stmt, err := json.Marshal(entry)
	if err != nil {
		return res
	}
	key := append(loadCacheKey(ctx, buildDir), "entryroots", string(stmt))
	if strictFrom(ctx) {
		key = append(key, "strict")
	}
	b, err := runCached(ctx, "entryroots", key, func() ([]byte, error) {
		loaded, err := load()
		if err != nil {
			return nil, err
		}
		return json.Marshal(resolveEntrypoints(loaded.Packages, entry, buildDir, strictFrom(ctx)).disclosure(loaded.Packages, buildDir))
	})
	if err != nil {
		return res
	}
	var rec plugin.EntryRootRecord
	if json.Unmarshal(b, &rec) != nil || rec.Lane == "" {
		return res
	}
	res.EntryRoots = &rec
	return res
}
