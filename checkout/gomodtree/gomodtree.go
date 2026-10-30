// Package gomodtree finds the Go modules in a source tree that a build root's own module graph
// leaves out. It is apart from package checkout so that checkout, which package plugin imports,
// keeps golang.org/x/mod out of every module that builds against plugin.
package gomodtree

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
)

// Nested returns the directories below dir that hold a go.mod of their own and that dir's
// module graph does not include: modules the go command resolves on their own, so resolving dir's
// module never sees what they require. A module a go.work in dir lists, or one dir/go.mod requires
// and replaces with its directory, is in that graph and is not returned. Paths are slash-separated,
// relative to dir, and sorted. A limit above zero stops the walk once that many are found; zero or
// less finds them all.
//
// Unlike checkout.FindGoModuleRoot the walk is unbounded: a module four levels down hides its requirements
// as well as one a level down. It skips what the go command never treats as module source: ".git",
// "testdata", "vendor", and any directory whose name starts with "." or "_". A go.work or go.mod
// that cannot be read or parsed includes nothing, so every nested module stays named.
func Nested(dir string, limit int) []string {
	included := includedModuleDirs(dir)
	var found []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree names no module; keep walking siblings.
		}
		if !d.IsDir() || path == dir {
			return nil
		}
		if name := d.Name(); name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return filepath.SkipDir
		}
		if included[path] {
			return nil
		}
		if fi, err := os.Stat(filepath.Join(path, "go.mod")); err != nil || fi.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil //nolint:nilerr // a path outside dir cannot be named relative to it.
		}
		found = append(found, filepath.ToSlash(rel))
		if limit > 0 && len(found) >= limit {
			return fs.SkipAll
		}
		return nil
	})
	sort.Strings(found)
	return found
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
