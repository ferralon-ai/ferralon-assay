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
	// Prefixed returns dir/name from each directory the command may run in, the file a
	// command told to treat dir as its package root (npm --prefix dir) reads, without looking
	// above it. dir must be a literal relative path with no .. part, inside the build and
	// reached through no symlink, and dir/name a regular file, read here, that the walk checks
	// as a surface on its own. With locks given, each of them that is there in dir must be a
	// regular file read here, reached through no symlink. nil when any is not.
	Prefixed(dir, name string, locks ...string) []string
}

// cursor is a Binder that also follows directory changes and other commands.
type cursor interface {
	Binder
	cd(words []string) // nil when the target is not literal
	other()            // a command that runs no installer and may change files
	// fork returns a cursor for a command started from here in a shell of its own, whose
	// directory changes do not reach this one.
	fork() cursor
	// sourced reports whether p, from every directory the command may run in, names an in-tree
	// script surface the walk checks on its own.
	sourced(p string) bool
	// at returns the one place a literal path names from the directory the command runs in,
	// keyed so that two keys are equal only when they name the same place; false when it names
	// no one place.
	at(p string) (string, bool)
	// present reports whether a literal path from the directory the command runs in may name
	// a file the build already holds.
	present(p string) bool
	// venv is the state of the venv rule at this command.
	venv() *venvMark
}

// venvMark is what the venv rule carries from command to command in one shell.
type venvMark struct {
	made   string // key of the venv the last command but for directory changes created, or ""
	open   int    // if, case and loop bodies the command is inside; below 0 when not known
	dangle bool   // the last line ended in &&, || or |
	lost   bool   // a cd that may not have run left the rule not knowing where the shell is
	chain  bool   // a cd after && moved the directory: known only while the && list goes on
}

// hostCursor is the set of host directories a command may run in.
type hostCursor struct {
	v       *Veto
	dirs    []string
	unknown bool
	mark    venvMark
	// wd is the one directory a CI shell unit runs in, which only the venv rule reads; "" when
	// it is not known.
	wd string
}

func (c *hostCursor) cd(words []string) {
	if c.wd != "" {
		n := ""
		if len(words) == 2 && words[0] != "popd" && words[1] != "-" && !strings.HasPrefix(words[1], "~") && !filepath.IsAbs(words[1]) {
			n = filepath.Join(c.wd, words[1])
		}
		if n == "" || !c.v.inRoot(n) || !isDir(n) {
			n = ""
		}
		c.wd = n
	}
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

func (c *hostCursor) fork() cursor {
	f := *c
	f.dirs = append([]string(nil), c.dirs...)
	return &f
}

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
	loc, ok := c.loc(p)
	if ok && filepath.IsAbs(p) {
		return "abs:" + loc, true
	}
	return "rel:" + loc, ok
}

func (c *hostCursor) present(p string) bool {
	loc, ok := c.loc(p)
	if !ok {
		return true
	}
	if filepath.IsAbs(p) && !c.v.inRoot(loc) {
		return false
	}
	_, there, known := c.v.stat(loc)
	return there || !known
}

// loc is the one place a literal path names from the directory the command runs in.
func (c *hostCursor) loc(p string) (string, bool) {
	switch {
	case p == "" || strings.ContainsAny(p, "$`*?[~"):
		return "", false
	case filepath.IsAbs(p):
		return filepath.Clean(p), true
	case c.mark.lost:
		return "", false
	case c.wd != "":
		return filepath.Join(c.wd, p), true
	case c.unknown || len(c.dirs) != 1:
		return "", false
	}
	return filepath.Join(c.dirs[0], p), true
}

func (c *hostCursor) venv() *venvMark { return &c.mark }

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

func (c *hostCursor) Prefixed(dir, name string, locks ...string) []string {
	if c.unknown || len(c.dirs) == 0 || dir == "" || filepath.IsAbs(dir) || strings.ContainsAny(dir, "$`*?[{~") {
		return nil
	}
	for _, part := range strings.Split(filepath.ToSlash(dir), "/") {
		if part == ".." {
			return nil
		}
	}
	found := make([]string, 0, len(c.dirs))
	for _, d := range c.dirs {
		f := filepath.Join(d, dir, name)
		// The walk yields no path through a symlinked directory, so read refuses one too. A
		// symlinked file is the lane's to read: a read that follows the link passes it, and
		// only unlinked (in packageFile) refuses it here, though Candidates withholds the run
		// on one regardless.
		if !c.v.packageFile(f) || !c.v.walkedSurface(f) {
			return nil
		}
		for _, l := range locks {
			lf := filepath.Join(d, dir, l)
			if _, err := os.Lstat(lf); err != nil && !c.v.spec.Absent(err) || err == nil && !c.v.packageFile(lf) {
				return nil
			}
		}
		found = append(found, f)
	}
	c.v.bind(name)
	for _, l := range locks {
		c.v.bind(l)
	}
	return found
}

// packageFile reports whether f is inside the build, reached through no symlink, and a regular
// file read here.
func (v *Veto) packageFile(f string) bool {
	return v.inRoot(f) && v.unlinked(f) && v.read(f)
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

// unlinked reports whether p, inside root, is a regular file reached from root through no
// symlink: every directory on the way, and p itself, is what it names.
func (v *Veto) unlinked(p string) bool {
	rel, err := filepath.Rel(v.root, p)
	if err != nil {
		return false
	}
	at := v.root
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		at = filepath.Join(at, part)
		fi, err := os.Lstat(at)
		if err != nil {
			return false
		}
		if last := i == len(parts)-1; last && !fi.Mode().IsRegular() || !last && !fi.IsDir() {
			return false
		}
	}
	return true
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
