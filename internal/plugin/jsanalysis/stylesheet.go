package jsanalysis

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// stylesheetExtensions are the extensions a relative import can name and, under stock bundler
// tooling, load no package code. A CSS Modules file (x.module.css) ends in one of them.
var stylesheetExtensions = map[string]bool{".css": true, ".scss": true, ".sass": true, ".less": true}

// stylesheetRunsNoCode reports whether the build-relative path rel, the target of a relative
// import, is a stylesheet whose load runs no code this lane leaves unread. That holds only when
// it has a stylesheet extension, it is a regular file in the build tree, and the tree holds no
// bundler or transform config: stock tooling handles a stylesheet with css-loader and
// style-loader, which put no package code on the reach path, but a config can route the
// extension to any loader, and it is not parsed to find out.
func (rs *resolver) stylesheetRunsNoCode(rel string) bool {
	return stylesheetExtensions[path.Ext(rel)] && rs.regularInTree(rel) && !rs.prog.styleToolingPresent()
}

// regularInTree reports whether the build-relative path rel names a regular file the build-tree
// walk visits at its real path: it resolves inside the root, through no node_modules or
// site-packages directory. A symlink on the way counts only when its target is such a place,
// as the walk reads a symlinked directory only through its target.
func (rs *resolver) regularInTree(rel string) bool {
	realRoot, err := filepath.EvalSymlinks(rs.prog.root)
	if err != nil {
		return false
	}
	real, err := filepath.EvalSymlinks(filepath.Join(rs.prog.root, filepath.FromSlash(rel)))
	if err != nil {
		return false
	}
	under, err := filepath.Rel(realRoot, real)
	if err != nil || under == "." || under == ".." || strings.HasPrefix(under, ".."+string(filepath.Separator)) {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(under), "/") {
		if buildTreeSkipped(part) {
			return false
		}
	}
	fi, err := os.Stat(real)
	return err == nil && fi.Mode().IsRegular()
}

// styleToolingPresent reports, once per program, whether the build tree holds anything that
// can change what a stylesheet import loads. Presence counts; nothing is parsed beyond a
// package.json's top-level keys. It counts:
//   - a bundler or framework config: webpack (any file or directory named webpack*, which
//     covers an ejected Create React App's config/), vite, rollup, rspack, esbuild (any esbuild*
//     file, a package.json script running esbuild, or a dependency on it), craco,
//     react-app-rewired's config-overrides.js, next, nuxt, svelte, astro, or a .parcelrc;
//   - a babel config (babel.config.*, .babelrc*), plugins or not;
//   - a package.json with a browser, babel or alias key or a jest.transform, or one that
//     cannot be read or decoded;
//   - a directory the walk cannot read, or a symlinked directory whose target the walk does not
//     itself read (one that leaves the tree included). A symlink to a file needs no rule of its
//     own: a config is recognised by its name, and a package.json that resolves outside the
//     tree cannot be read.
func (p *program) styleToolingPresent() bool {
	if p.styleTooling == nil {
		present := styleToolingIn(p.root)
		p.styleTooling = &present
	}
	return *p.styleTooling
}

func styleToolingIn(root string) bool {
	realRoot, rootErr := filepath.EvalSymlinks(root)
	if rootErr != nil {
		return true
	}
	walked := map[string]bool{}
	var linkedDirs []string
	present := false
	_ = walkBuildTree(root, func(e buildTreeEntry, err error) error {
		switch {
		case err != nil:
			present = true
		case e.Skipped:
			return nil
		case e.Symlink && buildTreeIsDir(e.Path):
			linkedDirs = append(linkedDirs, e.Path)
			return nil
		case styleToolingName(e.D.Name()):
			present = true
		case e.D.IsDir():
			if rel, err := filepath.Rel(root, e.Path); err == nil {
				walked[filepath.Join(realRoot, rel)] = true
			}
			return nil
		case e.D.Name() == "package.json":
			present = styleToolingManifest(root, e.Path)
		}
		if present {
			return filepath.SkipAll
		}
		return nil
	})
	if present {
		return true
	}
	for _, link := range linkedDirs {
		if target, err := filepath.EvalSymlinks(link); err != nil || !walked[target] {
			return true
		}
	}
	return false
}

// styleToolingConfigs are the config base names, before ".config.", that count wherever
// they appear.
var styleToolingConfigs = []string{"vite", "rollup", "rspack", "craco", "next", "nuxt", "svelte", "astro", "babel"}

func styleToolingName(name string) bool {
	switch {
	case strings.HasPrefix(name, "webpack"), strings.HasPrefix(name, "esbuild"),
		strings.HasPrefix(name, ".babelrc"), name == ".parcelrc", name == "config-overrides.js":
		return true
	}
	for _, c := range styleToolingConfigs {
		if strings.HasPrefix(name, c+".config.") {
			return true
		}
	}
	return false
}

// styleToolingManifest reports whether the package.json at file declares a stylesheet
// transform or a way to run esbuild, or cannot be read or decoded.
func styleToolingManifest(root, file string) bool {
	data, ok := readInRoot(root, file, maxInstalledManifest)
	if !ok {
		return true
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil || m == nil {
		return true
	}
	for _, key := range []string{"browser", "babel", "alias"} {
		if _, ok := m[key]; ok {
			return true
		}
	}
	if raw, ok := m["jest"]; ok {
		var jest map[string]json.RawMessage
		if json.Unmarshal(raw, &jest) != nil {
			return true
		}
		if _, ok := jest["transform"]; ok {
			return true
		}
	}
	for _, field := range []string{"scripts", "dependencies", "devDependencies", "optionalDependencies"} {
		raw, ok := m[field]
		if !ok {
			continue
		}
		var entries map[string]json.RawMessage
		if json.Unmarshal(raw, &entries) != nil {
			return true
		}
		for name, v := range entries {
			if field != "scripts" && name == "esbuild" {
				return true
			}
			if field == "scripts" && strings.Contains(string(v), "esbuild") {
				return true
			}
		}
	}
	return false
}
