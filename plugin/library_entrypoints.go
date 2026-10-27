package plugin

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// Library entry-point modes.
const (
	// LibraryEntrypointsAuto infers the entry points: the lane's rule for which of the build's
	// packages code outside the build can import.
	LibraryEntrypointsAuto = "auto"
	// LibraryEntrypointsNone declares that the build ships programs only: code outside the build
	// imports none of its packages.
	LibraryEntrypointsNone = "none"
	// LibraryEntrypointsPaths declares the entry points as the packages under Include.
	LibraryEntrypointsPaths = "paths"
)

// Sources of a resolved entry-point set.
const (
	// LibraryEntrypointsSourceAuto is a set the lane inferred with nothing declared.
	LibraryEntrypointsSourceAuto = "auto"
	// LibraryEntrypointsSourceDeclared is a set that rests on the caller's declaration.
	LibraryEntrypointsSourceDeclared = "declared"
)

// LibraryEntrypoints is the caller's statement of which of the build's packages code outside the
// build may import, and so call into past the build's own entry points. It is configuration handed
// to the lane, never read from the tree. The zero value is auto with nothing declared.
type LibraryEntrypoints struct {
	// Mode is one of the LibraryEntrypoints* modes; empty reads as auto.
	Mode string `json:"mode,omitempty"`
	// Include adds the packages under each path to the entry points (auto) or nominates them
	// (paths). Exclude takes the packages under each path out of either. A path is a directory
	// relative to Base, slash-separated, and covers the directory and everything below it; "." is
	// the whole tree.
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	// Base is the directory the paths are relative to: the repository root, which for a module
	// nested in the repository is above the build directory. Empty reads as the build directory.
	// The host sets it; the input never does.
	Base string `json:"base,omitempty"`
}

// ParseLibraryEntrypoints reads the library-entrypoints input: "auto", "none", or a list of paths
// separated by commas or whitespace, where "!path" excludes a path. Excluding paths with no path
// named keeps auto's inference for the rest; naming a path without "auto" nominates the entry
// points outright. Empty is auto. "./pkg/..." reads as "pkg".
func ParseLibraryEntrypoints(s string) (LibraryEntrypoints, error) {
	tokens := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' })
	var e LibraryEntrypoints
	auto, none := false, false
	for _, t := range tokens {
		switch t {
		case LibraryEntrypointsAuto:
			auto = true
			continue
		case LibraryEntrypointsNone:
			none = true
			continue
		}
		p, excluded := strings.CutPrefix(t, "!")
		clean, err := cleanEntrypointPath(p)
		if err != nil {
			return LibraryEntrypoints{}, fmt.Errorf("library-entrypoints: %q: %w", t, err)
		}
		if excluded {
			e.Exclude = append(e.Exclude, clean)
		} else {
			e.Include = append(e.Include, clean)
		}
	}
	switch {
	case none && (auto || len(e.Include) > 0 || len(e.Exclude) > 0):
		return LibraryEntrypoints{}, fmt.Errorf("library-entrypoints: none stands alone, got %q", s)
	case none:
		e.Mode = LibraryEntrypointsNone
	case auto || len(e.Include) == 0:
		e.Mode = LibraryEntrypointsAuto
	default:
		e.Mode = LibraryEntrypointsPaths
	}
	slices.Sort(e.Include)
	e.Include = slices.Compact(e.Include)
	slices.Sort(e.Exclude)
	e.Exclude = slices.Compact(e.Exclude)
	return e, nil
}

// cleanEntrypointPath canonicalizes one declared path, rejecting one that leaves the repository root.
func cleanEntrypointPath(p string) (string, error) {
	p = strings.TrimSuffix(p, "/...")
	if p == "..." {
		p = "."
	}
	switch {
	case p == "":
		return "", fmt.Errorf("empty path")
	case strings.Contains(p, `\`):
		return "", fmt.Errorf("use / to separate path elements")
	case path.IsAbs(p):
		return "", fmt.Errorf("path must be relative to the repository root")
	}
	clean := path.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("path leaves the repository root")
	}
	return clean, nil
}

// Removes reports whether e can take a package auto infers out of the entry points: none, a path
// list, or an exclusion. auto with paths added only adds.
func (e LibraryEntrypoints) Removes() bool {
	return e.Mode == LibraryEntrypointsNone || e.Mode == LibraryEntrypointsPaths || len(e.Exclude) > 0
}

// Declared reports whether e states anything beyond auto's inference.
func (e LibraryEntrypoints) Declared() bool {
	return e.Mode != "" && e.Mode != LibraryEntrypointsAuto || len(e.Include) > 0 || len(e.Exclude) > 0
}

// String renders e in the input's syntax.
func (e LibraryEntrypoints) String() string {
	var tokens []string
	switch e.Mode {
	case LibraryEntrypointsNone:
		return LibraryEntrypointsNone
	case LibraryEntrypointsPaths:
	default:
		if len(e.Include) > 0 || len(e.Exclude) == 0 {
			tokens = append(tokens, LibraryEntrypointsAuto)
		}
	}
	tokens = append(tokens, e.Include...)
	for _, p := range e.Exclude {
		tokens = append(tokens, "!"+p)
	}
	return strings.Join(tokens, ",")
}

// Under reports whether dir, slash-separated and relative to Base, lies under p.
func Under(dir, p string) bool {
	return p == "." || dir == p || strings.HasPrefix(dir, p+"/")
}

// ResolvedLibraryEntrypoints is the entry-point set a lane resolved for the build, and what it rests on.
type ResolvedLibraryEntrypoints struct {
	// Ecosystem is the PURL type of the packages the lane resolved ("golang", "maven", "nuget"); a
	// report holds one record per ecosystem.
	Ecosystem string `json:"ecosystem"`
	// Source is LibraryEntrypointsSourceAuto or LibraryEntrypointsSourceDeclared.
	Source string `json:"source"`
	// Input is the library-entrypoints statement the set was resolved from, in the input's syntax.
	Input string `json:"input"`
	// Packages are the entry points, in the lane's own package naming (a Go import path), sorted.
	// Empty means code outside the build calls into none of the build's packages.
	Packages []string `json:"packages"`
	// Unmatched are the declared paths, "!" kept on an exclusion, that matched none of the build's
	// packages. An unmatched Include leaves the set unknown, and the lane withholds what rests on it.
	Unmatched []string `json:"unmatched,omitempty"`
}
