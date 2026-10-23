package jsanalysis

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
)

// yarnrcKeys are the .yarnrc settings that cannot change which packages an install places.
var yarnrcKeys = map[string]bool{
	"registry": true, "network-timeout": true, "yarn-path": true, "lastUpdateCheck": true,
	"--frozen-lockfile": true, "--install.frozen-lockfile": true,
	"--pure-lockfile": true, "--install.pure-lockfile": true,
	"ignore-engines": true, "--ignore-engines": true, "--install.ignore-engines": true,
	"disable-self-update-check": true, "save-prefix": true,
}

// addYarnClassic places the packages of the yarn classic lock data at root (build-relative
// prefix) in a new semantic region. Anything the lane cannot read exactly leaves the layout
// incomplete, with the lock's pins kept as unread entries for scoped disclosure.
func (l *depLayout) addYarnClassic(prefix, root, lockPath string, data []byte) {
	r, ok := readYarnClassic(prefix, root, data)
	if !ok {
		l.incomplete = true
		l.addUnplaced(lockPath, root)
		return
	}
	l.regions = append(l.regions, r)
}

func readYarnClassic(prefix, root string, data []byte) (*depRegion, bool) {
	if !strings.Contains(string(data[:min(len(data), 512)]), "# yarn lockfile v1") {
		return nil, false
	}
	if !yarnrcOK(root) {
		return nil, false
	}
	r := newDepRegion(prefix)
	blocks := parseYarnClassic(data)
	table := map[string]*depEntry{}
	entries := make([]*depEntry, len(blocks))
	for i, b := range blocks {
		name := ""
		for _, d := range b.descriptors {
			n, rng := splitDescriptor(d)
			id, ok := yarnIdentity(n, rng)
			if !ok || name != "" && id != name {
				return nil, false
			}
			name = id
		}
		if name == "" || b.version == "" || !safeLoadName(name) {
			return nil, false
		}
		e := &depEntry{
			name: name, version: b.version, purl: makePURL(name, b.version),
			digest: yarnDigest(b), scriptsUnknown: true, deps: map[string]*depEntry{},
		}
		e.unreadable = e.digest == "" || !httpTarball(b.resolved)
		e.path = r.uniquePath("yarn-classic", name+"@"+b.version, name)
		r.place(e)
		for _, d := range b.descriptors {
			if table[d] != nil {
				return nil, false
			}
			table[d] = e
			n, _ := splitDescriptor(d)
			if !safeLoadName(n) {
				return nil, false
			}
			r.addCopy(n, e)
		}
		entries[i] = e
	}
	for i, b := range blocks {
		for _, n := range b.depOrder {
			t := table[n+"@"+b.deps[n]]
			if t == nil {
				return nil, false
			}
			entries[i].deps[n] = t
		}
	}

	if !exactCase(root, "package.json", ".yarnrc") {
		return nil, false
	}
	rootData, ok := readOptional(filepath.Join(root, "package.json"))
	if !ok {
		return nil, false
	}
	var rootMan struct {
		invManifest
		Resolutions map[string]string `json:"resolutions"`
	}
	if rootData != nil && json.Unmarshal(rootData, &rootMan) != nil {
		return nil, false
	}
	globs := parseWorkspaceGlobs(rootMan.Workspaces)
	if len(rootMan.Workspaces) > 0 && globs == nil && strings.TrimSpace(string(rootMan.Workspaces)) != "[]" {
		return nil, false
	}
	// yarn classic globs each pattern on its own and unions the results, so a "!" pattern
	// excludes nothing there; read as an exclusion it would drop a member yarn installs.
	if slices.ContainsFunc(globs, func(g string) bool { return strings.HasPrefix(g, "!") }) {
		return nil, false
	}
	members, ok := workspaceMembers(root, globs)
	if !ok {
		return nil, false
	}
	mans := map[string]*invManifest{".": &rootMan.invManifest}
	siblings := map[string]bool{}
	for _, dir := range members {
		data, err := readRegular(filepath.Join(root, filepath.FromSlash(dir), "package.json"))
		m := &invManifest{}
		if err != nil || json.Unmarshal(data, m) != nil {
			return nil, false
		}
		mans[dir] = m
		siblings[m.Name] = true
	}
	// rewritable are the descriptors yarn may rewrite to a resolution's pattern: every lock edge
	// and every workspace member's declared dependency. The root manifest's own are left as written.
	var rewritable []string
	for _, b := range blocks {
		for _, n := range b.depOrder {
			rewritable = append(rewritable, n+"@"+b.deps[n])
		}
	}
	for _, dir := range append([]string{"."}, members...) {
		m := mans[dir]
		deps := map[string]*depEntry{}
		for _, group := range []map[string]string{m.Dependencies, m.DevDependencies, m.OptionalDependencies} {
			for n, rng := range group {
				if dir != "." {
					rewritable = append(rewritable, n+"@"+rng)
				}
				switch t := table[n+"@"+rng]; {
				case t != nil:
					deps[n] = t
				case siblings[n]:
				default:
					return nil, false
				}
			}
		}
		r.addImporter(joinRel(prefix, dir), deps)
	}
	if !yarnResolutionsOK(rootMan.Resolutions, blocks, table, rewritable) {
		return nil, false
	}
	if len(blocks) == 0 && manifestsDeclareDeps(root) {
		return nil, false
	}
	return r, true
}

// yarnDigest returns a block's tarball digest: its integrity, else the sha1 a registry URL
// carries in its fragment.
func yarnDigest(b yarnBlock) string {
	if d := mapIntegrity(strings.Trim(b.integrity, `"'`)); d != "" {
		return d
	}
	_, frag, ok := strings.Cut(b.resolved, "#")
	if !ok || len(frag) != 40 || strings.Trim(strings.ToLower(frag), "0123456789abcdef") != "" {
		return ""
	}
	return "sha1:" + strings.ToLower(frag)
}

// httpTarball reports whether a resolved URL fetches a registry-style tarball over http(s).
func httpTarball(resolved string) bool {
	u, err := url.Parse(resolved)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" &&
		strings.HasSuffix(u.Path, ".tgz")
}

// yarnResolutionsOK accepts only resolutions whose effect the lock already shows. The key must be
// a bare or "**/" package name, and every block of that name must satisfy the value, as an exact
// pin or a range rangeSatisfied decides. yarn rewrites each rewritable descriptor of the name to
// the one pattern name@value, so for a range every such descriptor must already map to that
// pattern's block: two blocks that each satisfy the range still install as one. Any other key (a
// nested path) or value (a protocol, a range rangeSatisfied cannot decide) changes resolution in a
// way the lane does not replay.
func yarnResolutionsOK(res map[string]string, blocks []yarnBlock, table map[string]*depEntry, rewritable []string) bool {
	for k, v := range res {
		name := strings.TrimPrefix(k, "**/")
		if !safeLoadName(name) {
			return false
		}
		exact := exactVersion(v)
		for _, b := range blocks {
			for _, d := range b.descriptors {
				if n, _ := splitDescriptor(d); n == name && !(exact && b.version == v) && !rangeSatisfied(b.version, v) {
					return false
				}
			}
		}
		if exact {
			continue // every block of the name is v, so whichever block a rewrite lands on is the same
		}
		for _, d := range rewritable {
			if n, _ := splitDescriptor(d); n == name && table[d] != table[name+"@"+v] {
				return false
			}
		}
	}
	return true
}

// yarnrcOK reports whether root's .yarnrc is absent or sets only keys in yarnrcKeys.
func yarnrcOK(root string) bool {
	data, ok := readOptional(filepath.Join(root, ".yarnrc"))
	if !ok {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k := strings.Trim(strings.Fields(t)[0], `"'`)
		if !yarnrcKeys[k] {
			return false
		}
	}
	return true
}
