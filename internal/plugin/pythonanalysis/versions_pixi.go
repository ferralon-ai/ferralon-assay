package pythonanalysis

import (
	"maps"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- pixi --------------------------------------------------------------------------
//
// Pixi installs from its own tables, which this reader does not resolve: a pyproject that
// configures pixi, and a pixi.toml, leave the result partial. The PyPI names those tables
// declare are still read, each as an UNRESOLVED declaration no lock covers, so a project only
// pixi declares is in All rather than missing from it. Conda [dependencies] are not PyPI
// projects and are not read.

// pixiPyPIDeps returns the projects a pixi manifest's PyPI tables declare: [pypi-dependencies]
// and the same table under any feature, target, or feature target. root is the pixi table
// itself, [tool.pixi] in a pyproject or the whole of a pixi.toml. An entry that installs a
// local path is not a PyPI project and is skipped.
func pixiPyPIDeps(root map[string]any, source, dir string) ([]plugin.ResolvedDependency, []manifestOrigin) {
	var deps []plugin.ResolvedDependency
	addTable := func(tbl map[string]any) {
		pypi, _ := tbl["pypi-dependencies"].(map[string]any)
		for _, name := range slices.Sorted(maps.Keys(pypi)) {
			if entry, ok := pypi[name].(map[string]any); ok {
				if _, local := entry["path"]; local {
					continue
				}
			}
			deps = append(deps, pyResolved(name, "", false, source))
		}
	}
	addTargets := func(tbl map[string]any) {
		addTable(tbl)
		targets, _ := tbl["target"].(map[string]any)
		for _, t := range slices.Sorted(maps.Keys(targets)) {
			if sub, ok := targets[t].(map[string]any); ok {
				addTable(sub)
			}
		}
	}
	addTargets(root)
	features, _ := root["feature"].(map[string]any)
	for _, f := range slices.Sorted(maps.Keys(features)) {
		if sub, ok := features[f].(map[string]any); ok {
			addTargets(sub)
		}
	}
	return deps, originsFor(deps, manifestOrigin{dir: dir})
}

// pixiManifestDeps reads the PyPI names declared by every pixi.toml under root. read is false
// when the walk or a file fails, or a file does not decode.
func pixiManifestDeps(root string) (deps []plugin.ResolvedDependency, origins []manifestOrigin, read bool) {
	paths, read := walkManifests(root, func(path string) bool { return filepath.Base(path) == "pixi.toml" })
	for _, p := range paths {
		data, err := readRegular(p)
		if err != nil {
			read = read && absent(err)
			continue
		}
		var doc map[string]any
		if toml.Unmarshal(data, &doc) != nil {
			read = false
			continue
		}
		d, o := pixiPyPIDeps(doc, "pixi.toml", filepath.Dir(p))
		deps, origins = append(deps, d...), append(origins, o...)
	}
	return deps, origins, read
}
