// Package gomodtree finds the Go modules in a source tree that a build root's own module graph
// leaves out. It is apart from package checkout so that checkout, which package plugin imports,
// keeps golang.org/x/mod out of every module that builds against plugin.
package gomodtree

import (
	"go/version"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
)

// Module is one Go module the build root's module graph leaves out.
type Module struct {
	// Dir is the module's directory, slash-separated and relative to the walk's root.
	Dir string
	// Path is the module path its go.mod declares; "" when the go.mod declares none or does not parse.
	Path string
	// Bounded reports that Requires is every module the module's build can draw a package from: its
	// go.mod parses and declares go 1.17 or later, and from 1.17 a go.mod lists every module that
	// provides a package to its build, indirect ones included. An unbounded module may build
	// against anything.
	Bounded bool
	// Requires is the module paths its go.mod requires, and every module path a versioned replace
	// substitutes for one, sorted. Set only when Bounded.
	Requires []string
}

// Tree is what one walk found.
type Tree struct {
	// Modules is every module the walk found outside the build root's module graph, sorted by Dir.
	Modules []Module
	// Complete reports that the walk read every directory it entered. A directory it could not read
	// may hold a module it does not name.
	Complete bool
}

// Nested walks root and returns the modules below it, buildDir's own excluded, that buildDir's
// module graph does not include: modules the go command resolves on their own, so resolving
// buildDir's module never sees what they require. A module a go.work in buildDir lists, or one
// buildDir/go.mod requires and replaces with its directory, is in that graph and is not returned.
// root is the checkout root, which buildDir is or lies below: a sibling module beside buildDir
// hides its requirements as well as one nested inside it.
//
// Unlike checkout.FindGoModuleRoot the walk is unbounded: a module four levels down hides its
// requirements as well as one a level down. It skips what the go command never treats as module
// source: ".git", "testdata", "vendor", and any directory whose name starts with "." or "_", except
// buildDir and the directories above it. A go.work or go.mod of buildDir's that cannot be read or
// parsed includes nothing, so every other module stays named.
func Nested(root, buildDir string) Tree {
	root, buildDir = filepath.Clean(root), filepath.Clean(buildDir)
	included := includedModuleDirs(buildDir)
	included[buildDir] = true
	t := Tree{Complete: true}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory hides whatever modules it holds: the walk goes on through its
			// siblings, and the answer is incomplete.
			t.Complete = false
			return nil
		}
		if !d.IsDir() || path == root {
			return nil
		}
		if name := d.Name(); (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) && !within(buildDir, path) {
			return filepath.SkipDir
		}
		if included[path] {
			return nil
		}
		if fi, err := os.Stat(filepath.Join(path, "go.mod")); err != nil || fi.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil //nolint:nilerr // a path outside root cannot be named relative to it.
		}
		t.Modules = append(t.Modules, readModule(path, filepath.ToSlash(rel)))
		return nil
	})
	sort.Slice(t.Modules, func(i, j int) bool { return t.Modules[i].Dir < t.Modules[j].Dir })
	return t
}

// MayRequire reports whether a module the walk found may build against module: one whose path or
// requires name it or a path it lies under, one that is unbounded, or any module the walk may have
// missed because it was incomplete.
func (t Tree) MayRequire(module string) bool {
	if !t.Complete {
		return true
	}
	for _, m := range t.Modules {
		if !m.Bounded || under(module, m.Path) || slices.ContainsFunc(m.Requires, func(r string) bool { return under(module, r) }) {
			return true
		}
	}
	return false
}

// under reports whether the module path p is root or lies under it.
func under(p, root string) bool {
	return root != "" && (p == root || strings.HasPrefix(p, root+"/"))
}

// within reports whether dir is path or lies below it.
func within(dir, path string) bool {
	rel, err := filepath.Rel(path, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// readModule reads the module in dir, named rel.
func readModule(dir, rel string) Module {
	m := Module{Dir: rel}
	mf := parseIn(dir, "go.mod", modfile.Parse)
	if mf == nil {
		return m
	}
	if mf.Module != nil {
		m.Path = mf.Module.Mod.Path
	}
	if mf.Go == nil || !version.IsValid("go"+mf.Go.Version) || version.Compare("go"+mf.Go.Version, "go1.17") < 0 {
		return m
	}
	m.Bounded = true
	for _, r := range mf.Require {
		m.Requires = append(m.Requires, r.Mod.Path)
	}
	for _, r := range mf.Replace {
		if r.New.Version != "" {
			m.Requires = append(m.Requires, r.New.Path)
		}
	}
	slices.Sort(m.Requires)
	m.Requires = slices.Compact(m.Requires)
	return m
}

// includedModuleDirs returns the module directories dir's own module graph includes: every use
// directive of dir/go.work, and every directory dir/go.mod replaces a module it requires with.
func includedModuleDirs(dir string) map[string]bool {
	included := map[string]bool{}
	add := func(p string) {
		p = filepath.FromSlash(p)
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		included[filepath.Clean(p)] = true
	}
	if wf := parseIn(dir, "go.work", modfile.ParseWork); wf != nil {
		for _, u := range wf.Use {
			add(u.Path)
		}
	}
	if mf := parseIn(dir, "go.mod", modfile.Parse); mf != nil {
		required := make(map[string]bool, len(mf.Require))
		for _, r := range mf.Require {
			required[r.Mod.Path] = true
		}
		for _, r := range mf.Replace {
			if r.New.Version == "" && required[r.Old.Path] {
				add(r.New.Path)
			}
		}
	}
	return included
}

// parseIn reads dir/name and parses it with parse, returning nil when it is absent or unparseable.
func parseIn[T any](dir, name string, parse func(string, []byte, modfile.VersionFixer) (*T, error)) *T {
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	f, err := parse(path, data, nil)
	if err != nil {
		return nil
	}
	return f
}
