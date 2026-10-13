// Package buildtree is the one walk of a build directory that the dependency-version resolvers use
// to decide whether they have read every install surface in it, and the candidate list each
// lane's manifest classifier builds on top of that walk.
//
// The skip rule is fixed (see Skipped): a directory named node_modules or site-packages holds
// installed packages, not the build's own declarations, and is not entered. Nothing else is
// skipped, .git included. Walk never follows a symlink, and Candidates treats one that leaves
// the build dir as a surface it could not read.
package buildtree

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Skipped reports whether Walk visits a directory with this name without entering it.
func Skipped(name string) bool {
	return name == "node_modules" || name == "site-packages"
}

// Entry is one thing Walk visits.
type Entry struct {
	// Path is the entry's path as walked under root, never resolved through a symlink.
	Path string
	// D is the entry as the directory listing reports it; nil only when root itself cannot be
	// read.
	D fs.DirEntry
	// Symlink is set for a symlink. Walk never follows one.
	Symlink bool
	// Escapes is set for a symlink whose target does not resolve or resolves outside root.
	Escapes bool
	// Skipped is set for a directory (or a symlink to one) named node_modules or site-packages.
	// Walk visits it once and does not enter it.
	Skipped bool
}

// Walk visits every entry under root in lexical order, root included. It enters every
// directory except a Skipped one, and never follows a symlink. A directory it cannot read
// reaches visit a second time with err set; returning nil from that call moves on. visit may
// return filepath.SkipDir for a directory, or filepath.SkipAll.
func Walk(root string, visit func(e Entry, err error) error) error {
	realRoot, rootErr := filepath.EvalSymlinks(root)
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		e := Entry{Path: path, D: d}
		if err != nil {
			return visit(e, err)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			e.Symlink = true
			e.Escapes = rootErr != nil || !Inside(realRoot, path)
		}
		if path != root && Skipped(d.Name()) && (d.IsDir() || e.Symlink && isDir(path)) {
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

// Inside reports whether path, with every symlink in it resolved, lies under realRoot (itself
// already resolved). A path that does not resolve is not inside.
func Inside(realRoot, path string) bool {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(realRoot, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// templateExts are suffixes that wrap a file another tool renders or copies into place
// (requirements.txt.j2, package.json.hbs, pyproject.toml.example).
var templateExts = map[string]bool{
	".j2": true, ".jinja": true, ".jinja2": true, ".tmpl": true, ".tpl": true, ".template": true,
	".example": true, ".sample": true, ".dist": true, ".orig": true, ".bak": true,
	".hbs": true, ".handlebars": true, ".mustache": true, ".ejs": true, ".liquid": true, ".erb": true,
}

// TemplateInner returns path with a template suffix removed (requirements.txt.j2 becomes
// requirements.txt), so a lane classifies the name the rendered file will have. ok is false
// when path carries no template suffix.
func TemplateInner(path string) (string, bool) {
	ext := filepath.Ext(path)
	if !templateExts[strings.ToLower(ext)] {
		return "", false
	}
	return strings.TrimSuffix(path, ext), true
}

// Candidate is one install surface a lane's classifier found under the build dir.
type Candidate struct {
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

// HeadSize is how much of a file a content rule sees.
const HeadSize = 64 << 10

// Candidates walks root and returns, in walk order:
//
//   - every regular file, or symlink to a file inside root, that match accepts;
//   - every symlink that escapes root, every symlinked directory, and every directory or file
//     that cannot be read, since what they hold cannot be classified.
//
// match sees the path and up to HeadSize bytes of the file's content (nil when the content
// looks binary or the file is empty). fullyRead is asked only about a regular file match
// accepted; every other candidate is not fully read. Skipped directories yield nothing, unless
// they are symlinks leaving root.
func Candidates(root string, match func(path string, head []byte) (why string, ok bool), fullyRead func(path string) bool) []Candidate {
	var out []Candidate
	add := func(path, why string, read bool) {
		out = append(out, Candidate{Path: path, Why: why, FullyRead: read})
	}
	_ = Walk(root, func(e Entry, err error) error {
		switch {
		case err != nil:
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
		case e.Symlink && isDir(e.Path):
			add(e.Path, "symlinked directory", false)
			return nil
		case e.D.IsDir():
			return nil
		}
		if !e.Symlink && !e.D.Type().IsRegular() {
			return nil // a device, socket or pipe declares nothing, and reading a pipe would block
		}
		head, err := Head(e.Path)
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
	return out
}

// Head returns up to HeadSize bytes of the file at path, or nil when they look binary (contain
// a NUL byte).
func Head(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, HeadSize)
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

// AllFullyRead reports whether every candidate is fully read.
func AllFullyRead(cs []Candidate) bool {
	for _, c := range cs {
		if !c.FullyRead {
			return false
		}
	}
	return true
}
