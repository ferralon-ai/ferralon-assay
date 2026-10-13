// Package buildtree is the one walk of a build directory that the dependency-version resolvers use
// to decide whether they have read every install surface in it, and the candidate list each
// lane's manifest classifier builds on top of that walk.
//
// The skip rule is fixed (see Skipped): a directory named node_modules or site-packages holds
// installed packages, not the build's own declarations, and is not entered. Nothing else is
// skipped, .git included. Walk never follows a symlink, and Candidates treats one that leaves
// the build dir as a surface it could not read. A symlinked directory inside the build dir is
// read in full only through its target, when the walk itself enters that target at its real
// path; every other symlinked directory is a surface Candidates could not read.
package buildtree

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
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
// match sees the path and the file's Head: up to HeadSize bytes of its content, as UTF-8 when
// it starts with a byte-order mark, and nil when that content looks binary or is empty.
// fullyRead is asked only about a regular file match accepted; every other candidate is not
// fully read. Skipped directories yield nothing, unless they are symlinks leaving root.
func Candidates(root string, match func(path string, head []byte) (why string, ok bool), fullyRead func(path string) bool) []Candidate {
	var out []Candidate
	add := func(path, why string, read bool) {
		out = append(out, Candidate{Path: path, Why: why, FullyRead: read})
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
	_ = Walk(root, func(e Entry, err error) error {
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
		case e.Symlink && isDir(e.Path):
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
	for _, link := range linkedDirs {
		target, err := filepath.EvalSymlinks(link)
		if rootErr != nil || err != nil || !walked[target] {
			add(link, "symlinked directory the walk does not read", false)
		}
	}
	return out
}

// Head returns the file's content head (rawHead), or nil when it looks binary (contains a NUL
// byte) or is empty.
func Head(path string) ([]byte, error) {
	buf, err := rawHead(path)
	if err != nil || len(buf) == 0 || bytes.IndexByte(buf, 0) >= 0 {
		return nil, err
	}
	return buf, nil
}

// errNotRegular is returned for a path that names a pipe, socket, device or directory, or a
// symlink to one.
var errNotRegular = errors.New("not a regular file")

// rawHead returns the first HeadSize bytes of the file's canonical content, following symlinks,
// only when it is a regular file. A file's canonical content is its bytes, except when it starts
// with a byte-order mark and the text behind the mark decodes: then it is that text in UTF-8
// with the mark and one more U+FEFF trimmed (canonical), the bytes of the file's twin without
// the mark. pip decodes a requirements file by its BOM (Windows PowerShell 5 writes
// `pip freeze >` as UTF-16LE with one), so every rule judges a marked file exactly as it judges
// that twin.
//
// A non-regular target is refused without being opened, since opening a pipe with no writer
// blocks; the open itself does not block, and the opened descriptor must be the same regular
// file. Every refusal is an error, which callers treat as a file they could not read.
func rawHead(path string) ([]byte, error) {
	want, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !want.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, errNotRegular)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !got.Mode().IsRegular() || !os.SameFile(want, got) {
		return nil, fmt.Errorf("%s: changed while it was opened", path)
	}
	buf, err := readUpTo(f, nil, HeadSize)
	if err != nil {
		return nil, err
	}
	enc, ok := bomOf(buf)
	if !ok {
		return buf, nil
	}
	if len(buf) == HeadSize {
		// Every code unit past the trimmed marks yields at least one UTF-8 byte, so this many
		// raw bytes hold HeadSize canonical bytes, or the whole file. The extra four bytes hold
		// a second mark and, in UTF-16, the low half of a surrogate pair the read would split.
		if buf, err = readUpTo(f, buf, enc.mark+enc.unit*HeadSize+4); err != nil {
			return nil, err
		}
	}
	text, ok := canonical(enc, buf)
	if !ok {
		return buf[:min(len(buf), HeadSize)], nil
	}
	return text[:min(len(text), HeadSize)], nil
}

// readUpTo reads from f onto buf until buf holds size bytes or f ends.
func readUpTo(f *os.File, buf []byte, size int) ([]byte, error) {
	n := len(buf)
	buf = append(buf, make([]byte, size-n)...)
	m, err := io.ReadFull(f, buf[n:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n+m], nil
}

// NULHeadMatch is a content rule's fallback for a file whose Head was nil. A NUL does not stop
// every installer (pip and yarn v1 read past one in a comment), so it re-reads the head (rawHead,
// canonical for a marked file) and runs content on it twice: with every NUL removed, and with
// every NUL turned into a newline. A re-read that fails matches as "unreadable": the file went
// unread, which never proves anything absent. An empty file does not match.
func NULHeadMatch(path string, content func(path string, head []byte) (string, bool)) (string, bool) {
	raw, err := rawHead(path)
	if err != nil {
		return "unreadable", true
	}
	for _, head := range [][]byte{
		bytes.ReplaceAll(raw, []byte{0}, nil),
		bytes.ReplaceAll(raw, []byte{0}, []byte{'\n'}),
	} {
		if len(head) == 0 {
			continue
		}
		if why, ok := content(path, head); ok {
			return why + " (NUL in head)", true
		}
	}
	return "", false
}

type bomEncoding struct {
	mark, unit int
	order      binary.ByteOrder // nil for UTF-8
}

// bomOf reads the byte-order mark raw starts with. A UTF-32 mark is checked before UTF-16,
// whose little-endian mark it begins with.
func bomOf(raw []byte) (bomEncoding, bool) {
	switch {
	case bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}):
		return bomEncoding{3, 1, nil}, true
	case bytes.HasPrefix(raw, []byte{0xFF, 0xFE, 0, 0}):
		return bomEncoding{4, 4, binary.LittleEndian}, true
	case bytes.HasPrefix(raw, []byte{0, 0, 0xFE, 0xFF}):
		return bomEncoding{4, 4, binary.BigEndian}, true
	case bytes.HasPrefix(raw, []byte{0xFF, 0xFE}):
		return bomEncoding{2, 2, binary.LittleEndian}, true
	case bytes.HasPrefix(raw, []byte{0xFE, 0xFF}):
		return bomEncoding{2, 2, binary.BigEndian}, true
	}
	return bomEncoding{}, false
}

// canonical returns raw, which starts with enc's mark, as UTF-8 text without the mark and
// without one U+FEFF after it (pip's UTF-16 decoder consumes a second mark). A trailing partial
// code unit, or a high surrogate with its pair cut off, is where the read stopped, and is dropped.
// ok is false when the UTF-16 or UTF-32 text does not decode (an unpaired surrogate, a code point
// past U+10FFFF): the file is not text in that encoding, and its bytes are its content.
func canonical(enc bomEncoding, raw []byte) (text []byte, ok bool) {
	body := raw[enc.mark:]
	if enc.order == nil {
		return bytes.TrimPrefix(body, []byte("\ufeff")), true
	}
	var runes []rune
	switch enc.unit {
	case 2:
		units := make([]uint16, len(body)/2)
		for i := range units {
			units[i] = enc.order.Uint16(body[2*i:])
		}
		for i := 0; i < len(units); i++ {
			u := rune(units[i])
			switch {
			case utf16.IsSurrogate(u) && u < 0xDC00 && i+1 == len(units):
				// cut off by the read
			case utf16.IsSurrogate(u) && u < 0xDC00 && units[i+1] >= 0xDC00 && units[i+1] <= 0xDFFF:
				runes = append(runes, utf16.DecodeRune(u, rune(units[i+1])))
				i++
			case utf16.IsSurrogate(u):
				return nil, false
			default:
				runes = append(runes, u)
			}
		}
	case 4:
		for i := 0; i+4 <= len(body); i += 4 {
			r := rune(enc.order.Uint32(body[i:]))
			if !utf8.ValidRune(r) {
				return nil, false
			}
			runes = append(runes, r)
		}
	}
	if len(runes) > 0 && runes[0] == '\ufeff' {
		runes = runes[1:]
	}
	return []byte(string(runes)), true
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
