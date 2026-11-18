// Package gomod reads what a go.mod's directives make of a required module.
package gomod

import (
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

// Target is where a replace directive sends a module.
type Target struct {
	Path, Version string
	// Filesystem marks a local-directory replacement, which pins no verifiable version.
	Filesystem bool
}

// Replacement returns the replace directive that governs module at version: a directive naming
// that exact version wins over one naming the module alone, as in the go command.
func Replacement(mf *modfile.File, module, version string) (Target, bool) {
	var wildcard *modfile.Replace
	for _, r := range mf.Replace {
		if r.Old.Path != module {
			continue
		}
		if r.Old.Version == version && version != "" {
			return targetOf(r), true
		}
		if r.Old.Version == "" {
			wildcard = r
		}
	}
	if wildcard == nil {
		return Target{}, false
	}
	return targetOf(wildcard), true
}

func targetOf(r *modfile.Replace) Target { return NewTarget(r.New.Path, r.New.Version) }

// NewTarget returns the replacement target a directive or the go command's build list names by path
// and version.
func NewTarget(path, version string) Target {
	t := Target{Path: path, Version: version}
	if version == "" && (strings.HasPrefix(path, ".") || strings.HasPrefix(path, "/") || filepath.IsAbs(path)) {
		t.Filesystem = true
	}
	return t
}

// Pinned returns the version a build compiles module at when this target replaces it: only the same
// module at a version does, since that release's source is what is built. A fork or a local
// directory is code no release of module describes, so it pins nothing.
func (t Target) Pinned(module string) (version string, ok bool) {
	if t.Filesystem || t.Path != module || t.Version == "" {
		return "", false
	}
	return t.Version, true
}
