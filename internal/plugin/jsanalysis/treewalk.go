package jsanalysis

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// walkTree applies buildtree's read rule to root, which must already be resolved through
// filepath.EvalSymlinks. It calls file for every regular file, and every symlink to a regular
// file inside root, outside a Skipped directory. It calls fail for every entry whose contents
// the walk cannot read: a directory it cannot list (root included), a symlink that leaves root
// or does not resolve (a link cycle included), a symlink to something that is neither a regular
// file nor a directory (it is never opened), and a symlinked directory whose target the walk
// does not itself enter at its real path. A symlinked directory whose target the walk does
// enter is read through that target, once, and is not a failure. file may return
// filepath.SkipAll.
func walkTree(root string, file func(path, rel string, d fs.DirEntry) error, fail func(rel, why string)) {
	relOf := func(path string) string {
		rel, _ := filepath.Rel(root, path)
		return filepath.ToSlash(rel)
	}
	// walked holds every directory the walk entered and listed. root is resolved and the walk
	// never follows a symlink, so a walked path is its own real path.
	walked := map[string]bool{}
	var linkedDirs []string
	stopped := false
	visitFile := func(path string, d fs.DirEntry) error {
		err := file(path, relOf(path), d)
		stopped = err == filepath.SkipAll
		return err
	}
	err := buildtree.Walk(root, func(e buildtree.Entry, err error) error {
		switch {
		case err != nil:
			delete(walked, e.Path)
			fail(relOf(e.Path), "unreadable")
			if e.D != nil && e.D.IsDir() && e.Path != root {
				return filepath.SkipDir
			}
			return nil
		case e.Symlink && e.Escapes:
			fail(relOf(e.Path), "symlink leaves the build dir")
			return nil
		case e.Skipped:
			return nil
		case e.Symlink:
			info, err := os.Stat(e.Path)
			switch {
			case err != nil:
				fail(relOf(e.Path), "unreadable")
			case info.IsDir():
				linkedDirs = append(linkedDirs, e.Path)
			case info.Mode().IsRegular():
				return visitFile(e.Path, e.D)
			default:
				fail(relOf(e.Path), "symlink to a non-regular file") // opening a pipe would block
			}
			return nil
		case e.D.IsDir():
			walked[e.Path] = true
			return nil
		case !e.D.Type().IsRegular():
			return nil // a device, socket or pipe runs nothing, and reading a pipe would block
		}
		return visitFile(e.Path, e.D)
	})
	if err != nil {
		fail(".", "unreadable")
	}
	if stopped {
		return
	}
	for _, link := range linkedDirs {
		target, err := filepath.EvalSymlinks(link)
		if err != nil || !walked[target] {
			fail(relOf(link), "symlinked directory the walk does not read")
		}
	}
}
