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

func targetOf(r *modfile.Replace) Target {
	t := Target{Path: r.New.Path, Version: r.New.Version}
	if r.New.Version == "" && (strings.HasPrefix(r.New.Path, ".") || strings.HasPrefix(r.New.Path, "/") || filepath.IsAbs(r.New.Path)) {
		t.Filesystem = true
	}
	return t
}
