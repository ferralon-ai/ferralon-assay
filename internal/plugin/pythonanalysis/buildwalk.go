package pythonanalysis

// The walk of a build directory that the install scan and the committed-install scan share
// with the other lanes' manifest classifiers, copied from internal/plugin/buildtree at
// bc0233d until that package lands. The skip rule is fixed (see buildTreeSkipped): a directory
// named node_modules or site-packages holds installed packages, not the build's own
// declarations, and is not entered. Nothing else is skipped, .git included. The walk never
// follows a symlink; a symlink that leaves the build dir is reported so the caller fails
// closed on it. A symlinked directory inside the build dir is read in full only through its
// target, when the walk itself enters that target at its real path (see buildTreeLinks). A
// symlink inside the build dir to anything but a regular file or a directory is never opened
// (see buildTreeLinkedFile).

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// buildTreeSkipped reports whether buildTreeWalk visits a directory with this name without
// entering it.
func buildTreeSkipped(name string) bool {
	return name == "node_modules" || name == "site-packages"
}

// buildTreeEntry is one thing buildTreeWalk visits.
type buildTreeEntry struct {
	// Path is the entry's path as walked under root, never resolved through a symlink.
	Path string
	// D is the entry as the directory listing reports it; nil only when root itself cannot be
	// read.
	D fs.DirEntry
	// Symlink is set for a symlink. The walk never follows one.
	Symlink bool
	// Escapes is set for a symlink whose target does not resolve or resolves outside root.
	Escapes bool
	// Skipped is set for a directory (or a symlink to one) named node_modules or site-packages.
	// The walk visits it once and does not enter it.
	Skipped bool
}

// buildTreeWalk visits every entry under root in lexical order, root included. It enters
// every directory except a skipped one, and never follows a symlink. A directory it cannot
// read reaches visit a second time with err set; returning nil from that call moves on. visit
// may return filepath.SkipDir for a directory, or filepath.SkipAll.
func buildTreeWalk(root string, visit func(e buildTreeEntry, err error) error) error {
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

// buildTreeLinkedFile is buildtree.Candidates' check on a symlink inside root that is not a
// directory: why what it links cannot be read ("unreadable", or "symlink to a non-regular
// file" for a pipe, socket or device), or "" for a regular file. It never opens the target,
// since opening a pipe would block the walk.
func buildTreeLinkedFile(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return "unreadable"
	}
	if !fi.Mode().IsRegular() {
		return "symlink to a non-regular file"
	}
	return ""
}

func buildTreeIsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// buildTreeLinks decides, for one buildTreeWalk, which symlinked directories inside root are
// read in full: the rule buildtree.Candidates applies. A symlinked directory is read in full
// only when its target resolves inside root's real path to a directory the walk enters at that
// real path: not a skipped directory or anything under one, and not one it could not list. The
// walk never follows the link, so whatever the target holds is read once, at its real path.
type buildTreeLinks struct {
	root, realRoot string
	// walked holds the real path of every directory the walk entered and listed. The walk never
	// follows a symlink, so a walked path is root's real path joined with its path under root.
	walked     map[string]bool
	linkedDirs []string
}

func newBuildTreeLinks(root string) *buildTreeLinks {
	// If root does not resolve, realRoot is empty, no walked path matches a resolved target,
	// and every symlinked directory is unread.
	realRoot, _ := filepath.EvalSymlinks(root)
	return &buildTreeLinks{root: root, realRoot: realRoot, walked: map[string]bool{}}
}

func (l *buildTreeLinks) realOf(path string) string {
	rel, err := filepath.Rel(l.root, path)
	if err != nil {
		return ""
	}
	return filepath.Join(l.realRoot, rel)
}

// visit records one entry buildTreeWalk passed to its caller's visit, before the caller acts on
// it.
func (l *buildTreeLinks) visit(e buildTreeEntry, err error) {
	switch {
	case err != nil:
		delete(l.walked, l.realOf(e.Path))
	case e.Symlink && e.Escapes, e.Skipped:
	case e.Symlink && buildTreeIsDir(e.Path):
		l.linkedDirs = append(l.linkedDirs, e.Path)
	case e.D.IsDir():
		l.walked[l.realOf(e.Path)] = true
	}
}

// unread returns, in walk order, every symlinked directory inside root whose target the walk
// did not read. Call it after the walk.
func (l *buildTreeLinks) unread() []string {
	var out []string
	for _, link := range l.linkedDirs {
		target, err := filepath.EvalSymlinks(link)
		if err != nil || !l.walked[target] {
			out = append(out, link)
		}
	}
	return out
}
