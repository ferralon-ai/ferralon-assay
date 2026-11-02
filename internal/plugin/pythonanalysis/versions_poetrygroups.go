package pythonanalysis

import (
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/scriptsurface"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- poetry install group selection ------------------------------------------------
//
// poetry.lock resolves every dependency group, optional ones included, and every extra, but
// poetry install puts in place only the packages of the groups it selects: every group not
// marked optional, plus --with, less --without, or exactly --only. A package outside them is
// not installed by the run, and a copy already in the environment (a base image, a seeded
// virtualenv, system site-packages) keeps its own version, so its lock pin does not say what
// is installed. Such a package stays found, at no version: it may well be there.

// poetrySelection is the groups one poetry install selects, as its flags spell them.
type poetrySelection struct {
	only, with, without []string
	buildsRoot          bool
}

// poetryInstall is one allowed poetry install and the pyproject.toml files it reads.
type poetryInstall struct {
	poetrySelection
	pyprojects []string
}

// poetryInstalls records, by the build-tree path of the poetry.lock it installs, every allowed
// poetry install the script surfaces run.
type poetryInstalls map[string][]poetryInstall

// record adds the install sel describes to the lock beside each pyproject.toml it reads. It
// reports false, and the install withholds, when either cannot be named.
func (p poetryInstalls) record(sel poetrySelection, b scriptsurface.Binder) bool {
	pyprojects := b.Nearest("pyproject.toml")
	locks := b.Beside("pyproject.toml", "poetry.lock")
	if len(pyprojects) == 0 || len(locks) == 0 {
		return false
	}
	for _, l := range locks {
		l = filepath.Clean(l)
		p[l] = append(p[l], poetryInstall{poetrySelection: sel, pyprojects: pyprojects})
	}
	return true
}

// scope returns deps, read from the manifest at path, with every package no recorded poetry
// install of it is known to install left unresolved. A package resolves only when every
// recorded install of the lock installs it under every pyproject.toml that install may read:
// separate surfaces build separate environments, and each must hold the pinned version. A
// lock no recorded install names, and every other manifest, is returned as it is.
func (p poetryInstalls) scope(path string, deps []plugin.ResolvedDependency) []plugin.ResolvedDependency {
	runs := p[filepath.Clean(path)]
	if len(runs) == 0 {
		return deps
	}
	installed := poetryLockInstalled(path, runs)
	out := slices.Clone(deps)
	for i, d := range out {
		if !installed[normalizePyCoordinate(d.Coordinate)] {
			out[i].Version, out[i].Resolved = "", false
		}
	}
	return out
}

// poetryLockPackage is one locked package's group membership: poetry 2 writes the groups that
// pull it in, transitively, and poetry before 1.5 a category, "main" for one main pulls in and
// "dev" for one only other groups do. optional is true for one only an extra pulls in.
type poetryLockPackage struct {
	Name     string `toml:"name"`
	Optional any    `toml:"optional"`
	Groups   any    `toml:"groups"`
	Category any    `toml:"category"`
}

// poetryLockInstalled returns, by normalized name, whether every run installs every locked
// package of that name. It is empty when the lock cannot be decoded.
func poetryLockInstalled(lock string, runs []poetryInstall) map[string]bool {
	data, err := readRegular(lock)
	if err != nil {
		return nil
	}
	var doc struct {
		Package []poetryLockPackage `toml:"package"`
	}
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return nil
	}
	declared := map[string]*poetryGroups{}
	installed := map[string]bool{}
	seen := map[string]bool{}
	for _, pkg := range doc.Package {
		in := true
		for _, run := range runs {
			for _, m := range run.pyprojects {
				g, ok := declared[m]
				if !ok {
					g = readPoetryGroups(m)
					declared[m] = g
				}
				in = in && g != nil && g.installs(pkg, g.selected(run.poetrySelection))
			}
		}
		name := normalizePyCoordinate(pkg.Name)
		installed[name] = in && (!seen[name] || installed[name])
		seen[name] = true
	}
	return installed
}

// poetryGroups is the dependency groups a pyproject.toml declares: by normalized name, whether
// the group is optional, and each name as the manifest spells it.
type poetryGroups struct {
	optional map[string]bool
	spelled  map[string]bool
}

// readPoetryGroups reads the groups the pyproject.toml at path declares: main; each
// tool.poetry.group table, optional unless its optional key is false or absent; dev, for
// tool.poetry.dev-dependencies; and each [dependency-groups] entry, optional only as a
// tool.poetry.group table of the same name sets it. nil when the manifest cannot be read.
func readPoetryGroups(path string) *poetryGroups {
	data, err := readRegular(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Tool struct {
			Poetry struct {
				Group map[string]struct {
					Optional any `toml:"optional"`
				} `toml:"group"`
				DevDependencies any `toml:"dev-dependencies"`
			} `toml:"poetry"`
		} `toml:"tool"`
		DependencyGroups map[string]any `toml:"dependency-groups"`
	}
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return nil
	}
	g := &poetryGroups{optional: map[string]bool{}, spelled: map[string]bool{}}
	declare := func(name string, optional bool) {
		n := normalizePyCoordinate(name)
		g.optional[n] = g.optional[n] || optional
		g.spelled[name] = true
	}
	declare("main", false)
	if doc.Tool.Poetry.DevDependencies != nil {
		declare("dev", false)
	}
	for name := range doc.DependencyGroups {
		declare(name, false)
	}
	for name, t := range doc.Tool.Poetry.Group {
		optional := t.Optional != nil
		if v, ok := t.Optional.(bool); ok {
			optional = v
		}
		declare(name, optional)
	}
	return g
}

// selected returns, by normalized name, the groups sel installs, in poetry's order: --only
// alone when given, otherwise every group not optional, plus --with, less --without. A group
// --only or --with names counts only as the manifest spells it, since poetry 1.x matches the
// name as written; --without drops every spelling of its name.
func (g *poetryGroups) selected(sel poetrySelection) map[string]bool {
	out := map[string]bool{}
	pick := func(names []string) {
		for _, name := range names {
			if g.spelled[name] {
				out[normalizePyCoordinate(name)] = true
			}
		}
	}
	if len(sel.only) > 0 {
		pick(sel.only)
		return out
	}
	for name, optional := range g.optional {
		if !optional {
			out[name] = true
		}
	}
	pick(sel.with)
	for _, name := range sel.without {
		delete(out, normalizePyCoordinate(name))
	}
	return out
}

// installs reports whether an install of the groups selected puts pkg in place. A package
// only an extra pulls in never is: no allowed install selects an extra. A package whose
// membership cannot be read is installed only when every declared group is selected, and one
// that names a group the manifest does not declare never is.
func (g *poetryGroups) installs(pkg poetryLockPackage, selected map[string]bool) bool {
	if v, ok := pkg.Optional.(bool); pkg.Optional != nil && (!ok || v) {
		return false
	}
	all := func(skip string) bool {
		for name := range g.optional {
			if name != skip && !selected[name] {
				return false
			}
		}
		return true
	}
	switch {
	case pkg.Groups != nil:
		list, ok := pkg.Groups.([]any)
		in := false
		for _, e := range list {
			name, ok := e.(string)
			if !ok {
				return false
			}
			n := normalizePyCoordinate(name)
			if _, declared := g.optional[n]; !declared {
				return false
			}
			in = in || selected[n]
		}
		return ok && in
	case pkg.Category != nil:
		switch pkg.Category {
		case "main":
			return selected["main"]
		case "dev":
			return len(g.optional) > 1 && all("main")
		}
		return false
	}
	return all("")
}
