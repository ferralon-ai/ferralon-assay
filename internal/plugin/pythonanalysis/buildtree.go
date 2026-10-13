package pythonanalysis

// The build-tree walk below is copied from internal/plugin/buildtree/buildtree.go at commit
// bc0233d (blob 0219ca2d925dae344581fe87d7774381431c7e62), whose package is not on main yet:
// Skipped, Entry, Walk, Inside, isDir, Candidate, HeadSize, Candidates, Head and AllFullyRead,
// renamed with a buildTree prefix and otherwise unchanged. buildtree_test.go pins the same
// behavior. Once that package lands, callers move to it and this copy goes.
//
// The skip rule is fixed: a directory named node_modules or site-packages holds installed
// packages, not the build's own files, and is not entered. Nothing else is skipped, .git
// included. The walk never follows a symlink, and buildTreeCandidates treats one that leaves
// the build dir as a surface it could not read. A symlinked directory inside the build dir is
// read in full only through its target, when the walk itself enters that target at its real
// path; every other symlinked directory is a surface buildTreeCandidates could not read.

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// buildTreeSkipped reports whether walkBuildTree visits a directory with this name without entering it.
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
	// walkBuildTree visits it once and does not enter it.
	Skipped bool
}

// walkBuildTree visits every entry under root in lexical order, root included. It enters every
// directory except a Skipped one, and never follows a symlink. A directory it cannot read
// reaches visit a second time with err set; returning nil from that call moves on. visit may
// return filepath.SkipDir for a directory, or filepath.SkipAll.
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

// buildTreeInside reports whether path, with every symlink in it resolved, lies under realRoot (itself
// already resolved). A path that does not resolve is not inside.
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

// buildTreeCandidate is one install surface a lane's classifier found under the build dir.
type buildTreeCandidate struct {
	// Path is the file's path as walked under root, not resolved.
	Path string
	// Why names the rule that made it a candidate. It is diagnostic only.
	Why string
	// FullyRead is true only when the lane's resolver discovers this exact path, it is a regular
	// file inside root, it parses without error, and the parse captures everything the file can
	// cause to be installed. Any candidate with FullyRead false means the resolver cannot claim
	// to have enumerated the build's dependencies.
	FullyRead bool
}

// buildTreeHeadSize is how much of a file a content rule sees.
const buildTreeHeadSize = 64 << 10

// buildTreeCandidates walks root and returns, in walk order:
//
//   - every regular file, or symlink to a regular file inside root, that match accepts;
//   - every symlink that escapes root (or does not resolve, a link cycle included), every
//     symlink inside root to something that is neither a regular file nor a directory (opening a
//     pipe would block the walk), every directory or file that cannot be read, and every
//     symlinked directory whose target the walk does not itself read, since what they hold
//     cannot be classified.
//
// A symlinked directory is read in full, and is not a candidate, only when its target resolves
// inside root's real path to a directory the walk enters at that real path: not a Skipped
// directory or anything under one, and not one it could not list. The walk never follows the
// link, so whatever the target holds is classified once, at its real path.
//
// match sees the path and up to buildTreeHeadSize bytes of the file's content (nil when the content
// looks binary or the file is empty). fullyRead is asked only about a regular file match
// accepted; every other candidate is not fully read. Skipped directories yield nothing, unless
// they are symlinks leaving root.
func buildTreeCandidates(root string, match func(path string, head []byte) (why string, ok bool), fullyRead func(path string) bool) []buildTreeCandidate {
	var out []buildTreeCandidate
	add := func(path, why string, read bool) {
		out = append(out, buildTreeCandidate{Path: path, Why: why, FullyRead: read})
	}
	realRoot, rootErr := filepath.EvalSymlinks(root)
	// walked holds the real path of every directory the walk entered and listed. The walk never
	// follows a symlink, so a walked path is root's real path joined with its path under root.
	walked := map[string]bool{}
	realOf := func(path string) string {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return ""
		}
		return filepath.Join(realRoot, rel)
	}
	var linkedDirs []string
	_ = walkBuildTree(root, func(e buildTreeEntry, err error) error {
		switch {
		case err != nil:
			delete(walked, realOf(e.Path))
			add(e.Path, "unreadable", false)
			if e.D != nil && e.D.IsDir() && e.Path != root {
				return filepath.SkipDir
			}
			return nil
		case e.Symlink && e.Escapes:
			add(e.Path, "symlink leaves the build dir", false)
			return nil
		case e.Skipped:
			return nil
		case e.Symlink && buildTreeIsDir(e.Path):
			linkedDirs = append(linkedDirs, e.Path)
			return nil
		case e.D.IsDir():
			walked[realOf(e.Path)] = true
			return nil
		}
		if !e.Symlink && !e.D.Type().IsRegular() {
			return nil // a device, socket or pipe declares nothing, and reading a pipe would block
		}
		if e.Symlink {
			fi, err := os.Stat(e.Path)
			if err != nil {
				add(e.Path, "unreadable", false)
				return nil
			}
			if !fi.Mode().IsRegular() {
				add(e.Path, "symlink to a non-regular file", false) // opening a pipe would block
				return nil
			}
		}
		head, err := buildTreeHead(e.Path)
		if err != nil {
			add(e.Path, "unreadable", false)
			return nil
		}
		why, ok := match(e.Path, head)
		if !ok {
			return nil
		}
		add(e.Path, why, !e.Symlink && fullyRead(e.Path))
		return nil
	})
	for _, link := range linkedDirs {
		target, err := filepath.EvalSymlinks(link)
		if rootErr != nil || err != nil || !walked[target] {
			add(link, "symlinked directory the walk does not read", false)
		}
	}
	return out
}

// buildTreeHead returns up to buildTreeHeadSize bytes of the file at path, or nil when they look binary (contain
// a NUL byte).
func buildTreeHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, buildTreeHeadSize)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	buf = buf[:n]
	if n == 0 || bytes.IndexByte(buf, 0) >= 0 {
		return nil, nil
	}
	return buf, nil
}

// buildTreeAllFullyRead reports whether every candidate is fully read.
func buildTreeAllFullyRead(cs []buildTreeCandidate) bool {
	for _, c := range cs {
		if !c.FullyRead {
			return false
		}
	}
	return true
}
