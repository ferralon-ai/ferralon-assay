package pythonanalysis

// The lockfile model the load set reads: every locked distribution with its versions, its
// dependency edges, and whether the lockfile's own markers put it in the runtime install.
//
// Runtime is decided mechanically per format and only from what the lockfile records:
//   - uv.lock: the closure of every workspace member's main dependencies, following a
//     member's optional dependencies only for an extra some edge requests, and every optional
//     dependency of a non-member (over-approximated). Members' dependency groups and
//     unrequested extras are dev/optional.
//   - pdm.lock: a package whose groups include "default".
//   - poetry.lock: a package whose category or groups say "main". A lock-version 2.0 file
//     records neither, so it cannot tell runtime from dev.
//   - Pipfile.lock: carries no edges; never complete.
//
// A model that cannot tell runtime from dev for any one lockfile sets distinguishes=false,
// and nothing refutes.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

type lockModel struct {
	files         []string                   // relative paths of the lockfiles read
	versions      map[string]map[string]bool // PEP 503 name → locked versions
	edges         map[string]map[string]bool // PEP 503 name → dependency names
	members       map[string]bool            // uv workspace members: first-party, never refuted
	runtime       map[string]bool            // in the runtime install per the lockfile markers
	devLabel      map[string]string          // outside runtime: the dev/optional group reaching it
	distinguishes bool                       // every lockfile read can tell runtime from dev
}

var lockfileNames = map[string]bool{"uv.lock": true, "pdm.lock": true, "poetry.lock": true, "Pipfile.lock": true}

// loadLocks reads every lockfile under buildDir outside skipped and test directories. No
// lockfile, an unparseable one, or an edgeless format clears ls.complete.
func loadLocks(buildDir string, ls *loadSet) *lockModel {
	m := &lockModel{
		versions:      map[string]map[string]bool{},
		edges:         map[string]map[string]bool{},
		members:       map[string]bool{},
		runtime:       map[string]bool{},
		devLabel:      map[string]string{},
		distinguishes: true,
	}
	walkProjectFiles(buildDir, func(rel, abs string) {
		base := filepath.Base(rel)
		if !lockfileNames[base] {
			return
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			ls.gap("%s could not be read", rel)
			return
		}
		m.files = append(m.files, rel)
		var ok bool
		switch base {
		case "uv.lock":
			ok = m.readUV(data)
		case "pdm.lock":
			ok = m.readPDM(data)
		case "poetry.lock":
			ok = m.readPoetry(data)
		case "Pipfile.lock":
			ok = m.readPipfile(data)
			if ok {
				ls.gap("%s records no dependency edges", rel)
			}
		}
		if !ok {
			ls.gap("%s could not be parsed", rel)
		}
	})
	sort.Strings(m.files)
	if len(m.files) == 0 {
		m.distinguishes = false
		ls.gap("no lockfile: the installed distributions and their edges are unknown")
	}
	return m
}

func (m *lockModel) addVersion(name, version string) {
	if m.versions[name] == nil {
		m.versions[name] = map[string]bool{}
	}
	m.versions[name][strings.TrimSpace(version)] = true
}

func (m *lockModel) addEdge(from, to string) {
	if from == "" || to == "" || from == to {
		return
	}
	if m.edges[from] == nil {
		m.edges[from] = map[string]bool{}
	}
	m.edges[from][to] = true
}

// labelFrom marks every package reachable over edges from seeds, and not runtime, as reached
// through label (first label wins).
func (m *lockModel) labelFrom(seeds []string, label string) {
	seen := map[string]bool{}
	queue := append([]string(nil), seeds...)
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if seen[d] {
			continue
		}
		seen[d] = true
		if !m.runtime[d] && !m.members[d] && m.devLabel[d] == "" {
			m.devLabel[d] = label
		}
		for c := range m.edges[d] {
			queue = append(queue, c)
		}
	}
}

// --- uv.lock -------------------------------------------------------------------------

type uvLoadLock struct {
	Manifest struct {
		Members []string `toml:"members"`
	} `toml:"manifest"`
	Package []uvLoadPackage `toml:"package"`
}

type uvLoadPackage struct {
	Name                 string                 `toml:"name"`
	Version              string                 `toml:"version"`
	Source               map[string]any         `toml:"source"`
	Dependencies         []uvLoadDep            `toml:"dependencies"`
	OptionalDependencies map[string][]uvLoadDep `toml:"optional-dependencies"`
	DevDependencies      map[string][]uvLoadDep `toml:"dev-dependencies"`
}

type uvLoadDep struct {
	Name  string   `toml:"name"`
	Extra []string `toml:"extra"`
}

func (m *lockModel) readUV(data []byte) bool {
	var lock uvLoadLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return false
	}
	pkgs := map[string]uvLoadPackage{}
	members := map[string]bool{}
	for _, n := range lock.Manifest.Members {
		members[normalizePyCoordinate(n)] = true
	}
	for _, p := range lock.Package {
		name := normalizePyCoordinate(p.Name)
		if name == "" {
			continue
		}
		pkgs[name] = p
		if len(lock.Manifest.Members) == 0 {
			if _, ok := p.Source["editable"]; ok {
				members[name] = true
			}
			if _, ok := p.Source["virtual"]; ok {
				members[name] = true
			}
		}
	}
	for name, p := range pkgs {
		if members[name] {
			m.members[name] = true
			continue
		}
		m.addVersion(name, p.Version)
		for _, d := range p.Dependencies {
			m.addEdge(name, normalizePyCoordinate(d.Name))
		}
		for _, deps := range p.OptionalDependencies {
			for _, d := range deps {
				m.addEdge(name, normalizePyCoordinate(d.Name))
			}
		}
	}
	if len(members) == 0 {
		m.distinguishes = false
		return true
	}

	// Runtime closure from every member's main dependencies.
	type item struct {
		name   string
		extras []string
	}
	var queue []item
	for n := range members {
		queue = append(queue, item{name: n})
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i].name < queue[j].name })
	seenExtra := map[string]bool{}
	requested := map[string]map[string]bool{}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		key := it.name + "[" + strings.Join(it.extras, ",") + "]"
		if seenExtra[key] {
			continue
		}
		seenExtra[key] = true
		p, ok := pkgs[it.name]
		if !ok {
			continue
		}
		if !members[it.name] {
			m.runtime[it.name] = true
		}
		deps := append([]uvLoadDep(nil), p.Dependencies...)
		if members[it.name] {
			for _, e := range it.extras {
				if requested[it.name] == nil {
					requested[it.name] = map[string]bool{}
				}
				requested[it.name][e] = true
				deps = append(deps, p.OptionalDependencies[e]...)
			}
		} else {
			for _, ds := range p.OptionalDependencies {
				deps = append(deps, ds...)
			}
		}
		for _, d := range deps {
			queue = append(queue, item{name: normalizePyCoordinate(d.Name), extras: d.Extra})
		}
	}

	// Dev groups and unrequested extras of members label what only they reach.
	for _, n := range sortedKeys(members) {
		p := pkgs[n]
		for _, g := range sortedMapKeys(p.DevDependencies) {
			m.labelFrom(depNames(p.DevDependencies[g]), n+" dependency group "+g)
		}
		for _, e := range sortedMapKeys(p.OptionalDependencies) {
			if !requested[n][e] {
				m.labelFrom(depNames(p.OptionalDependencies[e]), n+"["+e+"] extra")
			}
		}
	}
	return true
}

func depNames(ds []uvLoadDep) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, normalizePyCoordinate(d.Name))
	}
	return out
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- pdm.lock ------------------------------------------------------------------------

type pdmLoadLock struct {
	Package []struct {
		Name         string   `toml:"name"`
		Version      string   `toml:"version"`
		Groups       []string `toml:"groups"`
		Dependencies []string `toml:"dependencies"`
	} `toml:"package"`
}

func (m *lockModel) readPDM(data []byte) bool {
	var lock pdmLoadLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return false
	}
	grouped := map[string][]string{}
	for _, p := range lock.Package {
		name := normalizePyCoordinate(p.Name)
		if name == "" {
			continue
		}
		m.addVersion(name, p.Version)
		for _, dep := range p.Dependencies {
			if child, _, _, _ := parseRequirementSpec(strings.TrimSpace(dep)); child != "" {
				m.addEdge(name, normalizePyCoordinate(child))
			}
		}
		if len(p.Groups) == 0 {
			m.distinguishes = false
			continue
		}
		grouped[name] = p.Groups
		for _, g := range p.Groups {
			if g == "default" {
				m.runtime[name] = true
			}
		}
	}
	for _, n := range sortedMapKeys(grouped) {
		if !m.runtime[n] {
			m.labelFrom([]string{n}, "pdm group "+strings.Join(grouped[n], ", "))
		}
	}
	return true
}

// --- poetry.lock ---------------------------------------------------------------------

type poetryLoadLock struct {
	Package []struct {
		Name         string              `toml:"name"`
		Version      string              `toml:"version"`
		Category     string              `toml:"category"`
		Groups       []string            `toml:"groups"`
		Dependencies map[string]any      `toml:"dependencies"`
		Extras       map[string][]string `toml:"extras"`
	} `toml:"package"`
}

func (m *lockModel) readPoetry(data []byte) bool {
	var lock poetryLoadLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return false
	}
	labels := map[string]string{}
	for _, p := range lock.Package {
		name := normalizePyCoordinate(p.Name)
		if name == "" {
			continue
		}
		m.addVersion(name, p.Version)
		for dep := range p.Dependencies {
			m.addEdge(name, normalizePyCoordinate(dep))
		}
		for _, specs := range p.Extras {
			for _, s := range specs {
				if child, _, _, _ := parseRequirementSpec(strings.TrimSpace(strings.SplitN(s, " ", 2)[0])); child != "" {
					m.addEdge(name, normalizePyCoordinate(child))
				}
			}
		}
		groups := p.Groups
		if p.Category != "" {
			groups = append(groups, p.Category)
		}
		if len(groups) == 0 {
			m.distinguishes = false
			continue
		}
		main := false
		for _, g := range groups {
			main = main || g == "main"
		}
		if main {
			m.runtime[name] = true
		} else {
			labels[name] = "poetry group " + strings.Join(groups, ", ")
		}
	}
	for _, n := range sortedMapKeys(labels) {
		m.labelFrom([]string{n}, labels[n])
	}
	return true
}

// --- Pipfile.lock --------------------------------------------------------------------

func (m *lockModel) readPipfile(data []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	for _, section := range []string{"default", "develop"} {
		var entries map[string]struct {
			Version string `json:"version"`
		}
		if body, ok := raw[section]; ok {
			if err := json.Unmarshal(body, &entries); err != nil {
				return false
			}
		}
		for name, v := range entries {
			n := normalizePyCoordinate(name)
			m.addVersion(n, strings.TrimPrefix(v.Version, "=="))
			if section == "default" {
				m.runtime[n] = true
			} else if !m.runtime[n] && m.devLabel[n] == "" {
				m.devLabel[n] = "Pipfile develop"
			}
		}
	}
	return true
}
