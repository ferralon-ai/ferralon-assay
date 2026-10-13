package pythonanalysis

import (
	"maps"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- Pipfile and [tool.poetry] declarations ------------------------------------

// pipfileNonPackageTables are the Pipfile tables that are not package categories. Every
// other table ([packages], [dev-packages], and any custom pipenv category) declares
// packages.
var pipfileNonPackageTables = map[string]bool{"source": true, "requires": true, "pipenv": true, "scripts": true}

// parsePipfile reads a Pipfile's package categories. Each package is an entry: an exact
// pin ("==2.3.0" or "2.3.0", or the same under a table's version key) resolves; anything
// else is UNRESOLVED. A local path or file install other than the project itself makes
// the file report false (see declaredEntry).
func parsePipfile(data []byte) ([]plugin.ResolvedDependency, bool) {
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	var out []plugin.ResolvedDependency
	readable := true
	for _, table := range slices.Sorted(maps.Keys(doc)) {
		pkgs, isTable := doc[table].(map[string]any)
		if !isTable || pipfileNonPackageTables[table] {
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(pkgs)) {
			d, keep, ok := declaredEntry(name, pkgs[name], "Pipfile")
			readable = readable && ok
			if keep {
				out = append(out, d)
			}
		}
	}
	return out, readable
}

// poetryProject is the subset of pyproject.toml that declares Poetry dependencies.
type poetryProject struct {
	Tool struct {
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// parsePoetryDependencies reads pyproject.toml's [tool.poetry.dependencies],
// [tool.poetry.dev-dependencies] and every [tool.poetry.group.<name>.dependencies]. The
// "python" key is the interpreter constraint, not a package. Pins resolve as for a
// Pipfile.
func parsePoetryDependencies(data []byte) ([]plugin.ResolvedDependency, bool) {
	var doc poetryProject
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	p := doc.Tool.Poetry
	tables := []map[string]any{p.Dependencies, p.DevDependencies}
	for _, g := range slices.Sorted(maps.Keys(p.Group)) {
		tables = append(tables, p.Group[g].Dependencies)
	}
	var out []plugin.ResolvedDependency
	readable := true
	for _, t := range tables {
		for _, name := range slices.Sorted(maps.Keys(t)) {
			if strings.EqualFold(name, "python") {
				continue
			}
			d, keep, ok := declaredEntry(name, t[name], "pyproject.toml")
			readable = readable && ok
			if keep {
				out = append(out, d)
			}
		}
	}
	return out, readable
}

// declaredEntry turns one Pipfile or Poetry dependency value into an entry. keep is false
// when the value installs the project itself (path "."). ok is false when it installs a
// local path or file whose contents could be any distribution at any version; the caller
// then treats the manifest like an unparseable one. A git, VCS or remote URL source names
// its project by key, so it is an UNRESOLVED entry.
func declaredEntry(name string, v any, source string) (d plugin.ResolvedDependency, keep, ok bool) {
	unresolved := pyResolved(name, "", false, source)
	switch x := v.(type) {
	case string:
		ver, exact := exactDeclaredPin(x)
		return pyResolved(name, ver, exact, source), true, true
	case map[string]any:
		for _, key := range []string{"path", "file"} {
			loc, has := x[key].(string)
			if !has {
				continue
			}
			if isSelfPath(loc) {
				return plugin.ResolvedDependency{}, false, true
			}
			if strings.Contains(loc, "://") && !strings.HasPrefix(strings.ToLower(loc), "file:") {
				return unresolved, true, true // remote archive
			}
			return unresolved, true, false
		}
		for _, key := range []string{"git", "hg", "svn", "bzr", "url"} {
			if _, has := x[key]; has {
				return unresolved, true, true
			}
		}
		if s, has := x["version"].(string); has {
			ver, exact := exactDeclaredPin(s)
			return pyResolved(name, ver, exact, source), true, true
		}
		return unresolved, true, true
	case []any: // Poetry multiple-constraint dependency: one table per marker set
		ok = true
		for _, e := range x {
			if _, _, eok := declaredEntry(name, e, source); !eok {
				ok = false
			}
		}
		return unresolved, true, ok
	}
	return unresolved, true, true
}

// exactDeclaredPin reports the version a Pipfile or Poetry specifier pins exactly: "==X"
// or a bare "X". Any operator, wildcard, comma clause or "*" is not an exact pin.
func exactDeclaredPin(spec string) (string, bool) {
	s := strings.TrimSpace(spec)
	if rest, cut := strings.CutPrefix(s, "=="); cut {
		s = strings.TrimSpace(rest)
	}
	if s == "" || s[0] < '0' || s[0] > '9' {
		return "", false
	}
	for _, c := range s {
		if !isProjectNameRune(c) && c != '+' && c != '!' {
			return "", false
		}
	}
	return s, true
}

// isSelfPath reports whether a local install path names the project's own directory.
func isSelfPath(p string) bool {
	p = strings.TrimSpace(p)
	if i := strings.IndexByte(p, '['); i >= 0 { // ".[dev]" installs the project with extras
		p = p[:i]
	}
	p = strings.TrimRight(p, "/")
	return p == "."
}
