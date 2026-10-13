package jsanalysis

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// buildTreeSkipped reports whether walkBuildTree visits a directory with this name without
// entering it: node_modules and site-packages hold installed packages, not the build's own
// files. Nothing else is skipped, .git included. This is the shared build-tree walker rule;
// keep it identical to internal/plugin/buildtree's walker.
func buildTreeSkipped(name string) bool {
	return name == "node_modules" || name == "site-packages"
}

// buildTreeEntry is one thing walkBuildTree visits.
type buildTreeEntry struct {
	// Path is the entry's path as walked under root, never resolved through a symlink.
	Path string
	// D is the entry as the directory listing reports it; nil only when root itself cannot be
	// read.
	D fs.DirEntry
	// Symlink is set for a symlink. walkBuildTree never follows one.
	Symlink bool
	// Escapes is set for a symlink whose target does not resolve or resolves outside root.
	Escapes bool
	// Skipped is set for a directory (or a symlink to one) named node_modules or site-packages.
	Skipped bool
}

// walkBuildTree visits every entry under root in lexical order, root included. It enters
// every directory except a skipped one, which it still visits, and never follows a symlink.
// A directory it cannot read reaches visit a second time with err set; returning nil from
// that call moves on. visit may return filepath.SkipDir for a directory, or filepath.SkipAll.
func walkBuildTree(root string, visit func(e buildTreeEntry, err error) error) error {
	realRoot, rootErr := filepath.EvalSymlinks(root)
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		e := buildTreeEntry{Path: path, D: d}
		if err != nil {
			return visit(e, err)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			e.Symlink = true
			e.Escapes = rootErr != nil || !buildTreeInside(realRoot, path)
		}
		if path != root && buildTreeSkipped(d.Name()) && (d.IsDir() || e.Symlink && buildTreeIsDir(path)) {
			e.Skipped = true
			if err := visit(e, nil); err != nil {
				return err
			}
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		return visit(e, nil)
	})
}

// buildTreeInside reports whether the symlink at path resolves to a location under realRoot.
func buildTreeInside(realRoot, path string) bool {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(realRoot, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func buildTreeIsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
