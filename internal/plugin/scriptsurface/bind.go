package scriptsurface

import (
	"os"
	"path/filepath"
	"strings"
)

// Binder resolves the files a command reads from the directory it runs in.
type Binder interface {
	// File reports whether p, from the command's directory, is a file read here and unchanged.
	File(p string) bool
	// Hosts is File, returning the build-tree files p names, one per directory the command may
	// run in or Dockerfile source it was copied from; nil when File is false.
	Hosts(p string) []string
	// Nearest returns the nearest name at or above the command's directory, one per directory
	// the command may run in, each read here and unchanged; with locks given, the nearest of
	// them at or above each must be read here and unchanged too. nil when any is not.
	Nearest(name string, locks ...string) []string
}

// cursor is a Binder that also follows directory changes and other commands.
type cursor interface {
	Binder
	cd(words []string) // nil when the target is not literal
	other()            // a command that runs no installer and may change files
	// sourced reports whether p, from every directory the command may run in, names an in-tree
	// script surface the walk checks on its own.
	sourced(p string) bool
	// at returns the one place a literal path names from the directory the command runs in,
	// keyed so that two keys are equal only when they name the same place; false when it names
	// no one place.
	at(p string) (string, bool)
	// venv is the key of the virtual environment the last command other than a directory
	// change created, or "".
	venv() *string
}

// hostCursor is the set of host directories a command may run in.
type hostCursor struct {
	v       *Veto
	dirs    []string
	unknown bool
	made    string
}

func (c *hostCursor) cd(words []string) {
	if c.unknown {
		return
	}
	if len(words) != 2 || words[0] == "popd" || words[1] == "-" || strings.HasPrefix(words[1], "~") || filepath.IsAbs(words[1]) {
		c.unknown = true
		return
	}
	for i, d := range c.dirs {
		n := filepath.Join(d, words[1])
		if !c.v.inRoot(n) || !isDir(n) {
			c.unknown = true
			return
		}
		c.dirs[i] = n
	}
}

func (c *hostCursor) other() {}

func (c *hostCursor) merge(o *hostCursor) {
	c.unknown = c.unknown || o.unknown
	for _, d := range o.dirs {
		seen := false
		for _, e := range c.dirs {
			seen = seen || e == d
		}
		if !seen {
			c.dirs = append(c.dirs, d)
		}
	}
}

func (c *hostCursor) File(p string) bool { return c.Hosts(p) != nil }

func (c *hostCursor) sourced(p string) bool {
	if c.unknown || len(c.dirs) == 0 || p == "" || filepath.IsAbs(p) || strings.ContainsAny(p, "*?[~") {
		return false
	}
	for _, d := range c.dirs {
		if !c.v.walkedSurface(filepath.Join(d, p)) {
			return false
		}
	}
	return true
}

func (c *hostCursor) at(p string) (string, bool) {
	switch {
	case p == "" || strings.ContainsAny(p, "$`*?[~"):
		return "", false
	case filepath.IsAbs(p):
		return "abs:" + filepath.Clean(p), true
	case c.unknown || len(c.dirs) != 1:
		return "", false
	}
	return "rel:" + filepath.Join(c.dirs[0], p), true
}

func (c *hostCursor) venv() *string { return &c.made }

func (c *hostCursor) Hosts(p string) []string {
	if c.unknown || len(c.dirs) == 0 || p == "" || filepath.IsAbs(p) || strings.ContainsAny(p, "*?[~") {
		return nil
	}
	hosts := make([]string, 0, len(c.dirs))
	for _, d := range c.dirs {
		full := filepath.Join(d, p)
		if !c.v.inRoot(full) || !c.v.read(full) {
			return nil
		}
		hosts = append(hosts, full)
	}
	c.v.bind(p)
	return hosts
}

func (c *hostCursor) Nearest(name string, locks ...string) []string {
	if c.unknown || len(c.dirs) == 0 {
		return nil
	}
	var found []string
	for _, d := range c.dirs {
		hit := ""
		for dir := d; c.v.inRoot(dir); dir = filepath.Dir(dir) {
			f := filepath.Join(dir, name)
			regular, there, known := c.v.stat(f)
			if !known || there && !regular {
				return nil // npm or pip would stop here, at a file this cannot read
			}
			if regular {
				hit = f
				break
			}
			if dir == c.v.root {
				break
			}
		}
		if hit == "" || !c.v.read(hit) || len(locks) > 0 && !c.lockAbove(filepath.Dir(hit), locks) {
			return nil
		}
		found = append(found, hit)
	}
	c.v.bind(name)
	for _, l := range locks {
		c.v.bind(l)
	}
	return found
}

// lockAbove reports whether the nearest of locks at or above dir, inside root, is read here.
func (c *hostCursor) lockAbove(dir string, locks []string) bool {
	for ; c.v.inRoot(dir); dir = filepath.Dir(dir) {
		for _, l := range locks {
			f := filepath.Join(dir, l)
			switch regular, there, known := c.v.stat(f); {
			case !known || there && !regular:
				return false
			case regular:
				return c.v.read(f)
			}
		}
		if dir == c.v.root {
			break
		}
	}
	return false
}

// stat reports whether path, followed through symlinks, is a regular file and whether
// it is there at all. known is false when it is there but could not be examined, which never
// stands for its absence.
func (v *Veto) stat(p string) (regular, there, known bool) {
	fi, err := os.Stat(p)
	if err != nil {
		return false, false, v.spec.Absent(err)
	}
	return fi.Mode().IsRegular(), true, true
}

// glob lists what a COPY source pattern matches. ok is false when the pattern has a
// meta character before its last element or its directory is there but could not be listed:
// filepath.Glob drops such errors, and a match it did not list may be copied anyway.
func (v *Veto) glob(pattern string) (matches []string, ok bool) {
	dir, base := filepath.Split(pattern)
	if strings.ContainsAny(dir, "*?[\\") {
		return nil, false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, v.spec.Absent(err)
	}
	for _, e := range entries {
		m, err := filepath.Match(base, e.Name())
		if err != nil {
			return nil, false
		}
		if m {
			matches = append(matches, filepath.Join(dir, e.Name()))
		}
	}
	return matches, true
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
