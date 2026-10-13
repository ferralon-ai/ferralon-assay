package jsanalysis

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// gitIndex is what the git index of the checkout holding the build dir says about
// node_modules: a tree that .gitignore excludes can still be tracked (added before the
// ignore entry, or with add -f), and a tracked tree ships with the repo.
type gitIndex struct {
	none   bool     // no checkout above the build dir
	bad    bool     // an index the reader cannot parse: everything counts as tracked
	prefix string   // build dir relative to the checkout root, slash-separated ("" at the root)
	paths  []string // tracked paths containing a node_modules segment
}

// tracked reports whether the index records a file under build-relative directory rel.
func (g *gitIndex) tracked(rel string) bool {
	if g.none {
		return false
	}
	if g.bad {
		return true
	}
	dir := path.Join(g.prefix, rel)
	for _, p := range g.paths {
		if p == dir || strings.HasPrefix(p, dir+"/") {
			return true
		}
	}
	return false
}

// readGitIndex finds the checkout holding build (a .git directory, or a .git file naming
// a worktree's or submodule's git dir) and reads its index. It understands index versions 2
// and 3; version 4 prefix-compresses paths and, like any other read or parse failure,
// counts as tracking everything.
func readGitIndex(build string) *gitIndex {
	for dir := build; ; {
		gp := filepath.Join(dir, ".git")
		fi, err := os.Lstat(gp)
		switch {
		case err == nil:
			g := &gitIndex{bad: true}
			rel, err := filepath.Rel(dir, build)
			if err != nil {
				return g
			}
			if rel != "." {
				g.prefix = filepath.ToSlash(rel)
			}
			idx := filepath.Join(gp, "index")
			if !fi.IsDir() {
				data, err := readRegular(gp)
				if err != nil {
					return g
				}
				gd, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir:")
				if !ok {
					return g
				}
				gd = strings.TrimSpace(gd)
				if !filepath.IsAbs(gd) {
					gd = filepath.Join(dir, gd)
				}
				idx = filepath.Join(gd, "index")
			}
			data, err := readRegular(idx)
			if errors.Is(err, fs.ErrNotExist) {
				return &gitIndex{prefix: g.prefix} // nothing staged, nothing tracked
			}
			if err != nil {
				return g
			}
			paths, ok := indexPaths(data)
			if !ok {
				return g
			}
			g.bad, g.paths = false, paths
			return g
		case !errors.Is(err, fs.ErrNotExist):
			return &gitIndex{bad: true}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return &gitIndex{none: true}
		}
		dir = parent
	}
}

// indexPaths parses a version 2 or 3 index and returns the entry paths that contain a
// node_modules segment.
func indexPaths(data []byte) ([]string, bool) {
	if len(data) < 12 || string(data[:4]) != "DIRC" {
		return nil, false
	}
	ver := binary.BigEndian.Uint32(data[4:8])
	if ver != 2 && ver != 3 {
		return nil, false
	}
	n := binary.BigEndian.Uint32(data[8:12])
	var out []string
	off := 12
	for i := uint32(0); i < n; i++ {
		const fixed = 62 // stat fields, object id, flags
		if off+fixed > len(data) {
			return nil, false
		}
		flags := binary.BigEndian.Uint16(data[off+60 : off+62])
		head := fixed
		if flags&0x4000 != 0 {
			if ver < 3 {
				return nil, false
			}
			head += 2
		}
		start := off + head
		if start > len(data) {
			return nil, false
		}
		end := bytes.IndexByte(data[start:], 0)
		if end < 0 {
			return nil, false
		}
		p := string(data[start : start+end])
		if seg := "/" + p + "/"; strings.Contains(seg, "/node_modules/") {
			out = append(out, p)
		}
		off += (head + end + 8) &^ 7
	}
	return out, true
}
