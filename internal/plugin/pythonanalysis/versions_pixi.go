package pythonanalysis

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
// and the same table under any feature, inline environment, target, or feature or environment
// target. root is the pixi table itself, [tool.pixi] in a pyproject or the whole of a pixi.toml.
// An entry that installs a source directory under the manifest's own is skipped when the walk
// reads that project's manifest itself (pixiInTreeSource).
func pixiPyPIDeps(root map[string]any, source, dir string) ([]plugin.ResolvedDependency, []manifestOrigin) {
	var deps []plugin.ResolvedDependency
	addTable := func(tbl map[string]any) {
		pypi, _ := tbl["pypi-dependencies"].(map[string]any)
		for _, name := range slices.Sorted(maps.Keys(pypi)) {
			if entry, ok := pypi[name].(map[string]any); ok && pixiInTreeSource(dir, entry["path"]) {
				continue
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
	// An environment is a list of features, or a table that may carry feature content inline.
	for _, key := range []string{"feature", "environments"} {
		tables, _ := root[key].(map[string]any)
		for _, k := range slices.Sorted(maps.Keys(tables)) {
			if sub, ok := tables[k].(map[string]any); ok {
				addTargets(sub)
			}
		}
	}
	return deps, originsFor(deps, manifestOrigin{dir: dir})
}

// pixiInTreeSource reports whether a pypi-dependencies path names a source directory under dir
// that holds a manifest the walk reads: no component the walk skips, no symlink, and a
// pyproject.toml, setup.py or setup.cfg in it. Anything else (a wheel or sdist, a path that
// leaves dir, a Windows or home-relative spelling, a file:// URL) may be a distribution the walk
// never reads, so it stays an entry.
func pixiInTreeSource(dir string, path any) bool {
	p, ok := path.(string)
	if !ok || strings.ContainsAny(p, `\:~`) || !filepath.IsLocal(p) {
		return false
	}
	lower := strings.ToLower(p)
	for _, ext := range []string{".whl", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip"} {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	for _, c := range strings.Split(filepath.Clean(p), string(filepath.Separator)) {
		if skipDir(c) {
			return false
		}
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	target := filepath.Join(dir, p)
	if real, err := filepath.EvalSymlinks(target); err != nil || real != filepath.Join(realDir, p) {
		return false
	}
	for _, m := range []string{"pyproject.toml", "setup.py", "setup.cfg"} {
		if fi, err := os.Lstat(filepath.Join(target, m)); err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	return false
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
