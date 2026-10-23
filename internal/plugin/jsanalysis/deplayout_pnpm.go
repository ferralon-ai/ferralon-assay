package jsanalysis

import (
	"encoding/json"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// pnpmLockRootKeys are the root keys of the pnpm lockfile versions the lane reads. Any other
// key (pnpmfileChecksum, packageExtensionsChecksum, one a later pnpm adds) records install-time
// input the lane does not model.
var pnpmLockRootKeys = map[string]bool{
	"lockfileVersion": true, "settings": true, "overrides": true, "patchedDependencies": true,
	"catalogs": true, "importers": true, "packages": true, "snapshots": true, "time": true,
	"ignoredOptionalDependencies": true, "specifiers": true, "dependencies": true,
	"devDependencies": true, "optionalDependencies": true, "dependenciesMeta": true,
	"onlyBuiltDependencies": true, "neverBuiltDependencies": true,
}

// pnpmManifestKeys are the package.json "pnpm" settings that cannot change what the lock pins
// beyond what the lane checks (overrides and patches are compared with the lock).
var pnpmManifestKeys = map[string]bool{
	"overrides": true, "patchedDependencies": true, "peerDependencyRules": true,
	"neverBuiltDependencies": true, "onlyBuiltDependencies": true, "ignoredBuiltDependencies": true,
	"allowedDeprecatedVersions": true, "updateConfig": true, "auditConfig": true,
	"requiredScripts": true, "supportedArchitectures": true, "ignoredOptionalDependencies": true,
	"executionEnv": true, "packageExtensions": true,
}

// pnpmWorkspaceKeys are the pnpm-workspace.yaml settings the lane accepts. Linker and hoist
// settings are among them: the phantom rule holds under every one of them.
var pnpmWorkspaceKeys = map[string]bool{
	"packages": true, "catalog": true, "catalogs": true, "savePrefix": true, "updateNotifier": true,
	"ignoreScripts": true, "minimumReleaseAge": true, "verifyDepsBeforeRun": true,
	"onlyBuiltDependencies": true, "ignoredBuiltDependencies": true, "neverBuiltDependencies": true,
	"strictDepBuilds": true, "nodeLinker": true, "hoist": true, "hoistPattern": true,
	"publicHoistPattern": true, "shamefullyHoist": true, "hoistWorkspacePackages": true,
	"virtualStoreDir": true, "virtualStoreDirMaxLength": true, "modulesDir": true,
	"packageImportMethod": true, "dedupePeerDependents": true, "autoInstallPeers": true,
	"resolvePeersFromWorkspaceRoot": true, "dedupeDirectDeps": true, "overrides": true,
	"patchedDependencies": true,
}

// maxPatchBytes caps one patch file read.
const maxPatchBytes = 4 << 20

// pnpmLock is one pnpm lock being placed.
type pnpmLock struct {
	region  *depRegion
	root    string
	version string
	doc     *ynode
	byKey   map[string]*depEntry
	keys    []string
	links   map[string]*depEntry
}

// addPnpm places the packages of the pnpm lock data at root (build-relative prefix) in a new
// semantic region. Anything the lane cannot read exactly leaves the layout incomplete, with the
// lock's pins kept as unread entries for scoped disclosure.
func (l *depLayout) addPnpm(prefix, root, lockPath string, data []byte) {
	r, ok := readPnpm(prefix, root, data)
	if !ok {
		l.incomplete = true
		l.addUnplaced(lockPath, root)
		return
	}
	l.regions = append(l.regions, r)
}

func readPnpm(prefix, root string, data []byte) (*depRegion, bool) {
	docs := splitYAMLDocs(string(data))
	var project string
	switch len(docs) {
	case 1:
		project = docs[0]
	case 2:
		env, err := parseYAMLSubset(docs[0])
		if err != nil || !pnpmEnvDocOK(env) {
			return nil, false
		}
		project = docs[1]
	default:
		return nil, false
	}
	doc, err := parseYAMLSubset(project)
	if err != nil {
		return nil, false
	}
	p := &pnpmLock{
		region: newDepRegion(prefix), root: root, doc: doc,
		version: doc.child("lockfileVersion").str(),
		byKey:   map[string]*depEntry{}, links: map[string]*depEntry{},
	}
	switch p.version {
	case "5.4", "6.0", "9.0":
	default:
		return nil, false
	}
	for _, k := range doc.keys {
		if !pnpmLockRootKeys[k] {
			return nil, false
		}
	}
	if doc.child("settings").child("excludeLinksFromLockfile").str() == "true" {
		return nil, false
	}
	cfg, ok := readPnpmConfig(root)
	if !ok || !p.entries() || !p.edges() || !p.importers() || !p.checkConfig(cfg) {
		return nil, false
	}
	return p.region, true
}

// pnpmEnvDocOK accepts the environment document pnpm 10 writes ahead of the project lock when
// it records only the package manager itself. Config dependencies run at install.
func pnpmEnvDocOK(env *ynode) bool {
	if env.child("lockfileVersion") == nil {
		return false
	}
	for _, k := range env.keys {
		switch k {
		case "lockfileVersion", "importers", "packages", "snapshots":
		default:
			return false
		}
	}
	imps, keys, ok := env.child("importers").mapping()
	if !ok {
		return false
	}
	for _, k := range keys {
		if k != "." {
			return false
		}
		groups, gkeys, ok := imps[k].mapping()
		if !ok {
			return false
		}
		for _, g := range gkeys {
			switch g {
			case "packageManagerDependencies":
			case "configDependencies":
				if deps, _, ok := groups[g].mapping(); !ok || len(deps) > 0 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

// entries places every package the lock pins.
func (p *pnpmLock) entries() bool {
	pkgs, pkeys, ok := p.doc.child("packages").mapping()
	if !ok {
		return false
	}
	keys, meta := pkeys, func(k string) *ynode { return pkgs[k] }
	if p.version == "9.0" {
		_, skeys, ok := p.doc.child("snapshots").mapping()
		if !ok {
			return false
		}
		keys = skeys
		meta = func(k string) *ynode { return pkgs[stripPeerSuffix(k)] }
	}
	for _, k := range keys {
		m := meta(k)
		if m == nil {
			return false
		}
		if _, _, ok := m.mapping(); !ok {
			return false
		}
		name, version, ok := p.identity(k, m)
		if !ok || !safeLoadName(name) {
			return false
		}
		e := &depEntry{name: name, version: version, purl: makePURL(name, version), scriptsUnknown: true}
		res := m.child("resolution")
		if res != nil && len(res.kids) == 0 && strings.HasPrefix(res.val, "{") {
			e.digest = mapIntegrity(extractIntegrity(res.val))
			e.unreadable = e.digest == "" || strings.Contains(res.val, "type: git") ||
				strings.Contains(res.val, "type: directory") || strings.Contains(res.val, "commit:")
		} else {
			e.unreadable = true
		}
		e.lockInstallScript = m.child("requiresBuild").str() == "true"
		e.path = p.region.uniquePath("pnpm", k, name)
		p.byKey[k] = e
		p.keys = append(p.keys, k)
		p.region.place(e)
	}
	return true
}

// identity reads the name and version a lock key and its metadata pin.
func (p *pnpmLock) identity(key string, m *ynode) (name, version string, ok bool) {
	switch p.version {
	case "9.0":
		name, version = splitNameAt(stripPeerSuffix(key))
	case "6.0":
		if rest, slash := strings.CutPrefix(key, "/"); slash {
			name, version = splitNameAt(stripPeerSuffix(rest))
		}
	case "5.4":
		if rest, slash := strings.CutPrefix(key, "/"); slash {
			segs := strings.Split(rest, "/")
			n := 2
			if strings.HasPrefix(rest, "@") {
				n = 3
			}
			if len(segs) == n {
				name = strings.Join(segs[:n-1], "/")
				version, _, _ = strings.Cut(segs[n-1], "_")
			}
		}
	}
	if v := m.child("name").str(); v != "" {
		name = v
	}
	if v := m.child("version").str(); v != "" {
		version = v
	}
	return name, version, name != "" && version != ""
}

// splitNameAt splits "name@version" at the '@' after the first character.
func splitNameAt(s string) (name, version string) {
	if len(s) < 2 {
		return "", ""
	}
	i := strings.IndexByte(s[1:], '@')
	if i < 0 {
		return "", ""
	}
	return s[:i+1], s[i+2:]
}

// stripPeerSuffix drops the "(peer@x)(patch_hash=…)" suffix of a pnpm 6/9 key.
func stripPeerSuffix(k string) string {
	if i := strings.IndexByte(k, '('); i > 0 {
		return k[:i]
	}
	return k
}

// target resolves one dependency value (a version, an alias key or a link) to its entry.
func (p *pnpmLock) target(name, v string) (*depEntry, bool) {
	if dir, ok := strings.CutPrefix(v, "link:"); ok {
		return p.link(name, dir), true
	}
	var cands []string
	switch p.version {
	case "9.0":
		cands = []string{name + "@" + v, v}
	case "6.0":
		cands = []string{"/" + name + "@" + v, v}
	case "5.4":
		cands = []string{"/" + name + "/" + v, v}
	}
	for _, c := range cands {
		if e := p.byKey[c]; e != nil {
			if name != e.name {
				p.region.addCopy(name, e)
			}
			return e, true
		}
	}
	return nil, false
}

// link returns the entry for a link: dependency: unread first-party code at a local version.
// pnpm runs no lifecycle script of a linked directory at install, so it is not scriptsUnknown.
func (p *pnpmLock) link(name, dir string) *depEntry {
	k := name + "\x00" + dir
	if e := p.links[k]; e != nil {
		return e
	}
	e := &depEntry{name: name, version: "0.0.0-local", purl: makePURL(name, "0.0.0-local"), unreadable: true}
	e.path = p.region.uniquePath("pnpm", "link+"+strconv.Itoa(len(p.links)), name)
	p.links[k] = e
	p.region.place(e)
	return e
}

// edges records each placed package's own dependency edges.
func (p *pnpmLock) edges() bool {
	src := p.doc.child("packages")
	if p.version == "9.0" {
		src = p.doc.child("snapshots")
	}
	for _, k := range p.keys {
		e, m := p.byKey[k], src.child(k)
		e.deps = map[string]*depEntry{}
		for _, g := range []string{"dependencies", "optionalDependencies"} {
			deps, ok := m.child(g).scalars()
			if !ok {
				return false
			}
			for _, name := range slices.Sorted(maps.Keys(deps)) {
				t, ok := p.target(name, deps[name])
				if !ok {
					return false
				}
				e.deps[name] = t
			}
		}
	}
	return true
}

// importers records the first-party projects the lock installs for.
func (p *pnpmLock) importers() bool {
	imps, dirs := map[string]*ynode{".": p.doc}, []string{"."}
	if n := p.doc.child("importers"); n != nil {
		var ok bool
		if imps, dirs, ok = n.mapping(); !ok {
			return false
		}
	}
	for _, dir := range dirs {
		imp := imps[dir]
		if dir != "." && (path.IsAbs(dir) || slices.Contains(strings.Split(dir, "/"), "..") || strings.Contains(dir, `\`)) {
			return false
		}
		if _, _, ok := imp.mapping(); !ok {
			return false
		}
		deps := map[string]*depEntry{}
		for _, g := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
			kids, keys, ok := imp.child(g).mapping()
			if !ok {
				return false
			}
			for _, name := range keys {
				v := kids[name].val
				if p.version != "5.4" {
					v = kids[name].child("version").str()
				}
				t, ok := p.target(name, v)
				if !ok {
					return false
				}
				deps[name] = t
			}
		}
		p.region.addImporter(joinRel(p.region.prefix, dir), deps)
	}
	return true
}

// pnpmConfig is the install-time configuration at a pnpm region root the lane compares with the
// lock.
type pnpmConfig struct {
	overrides map[string]string
	patches   map[string]string
	members   []string
	manifests map[string]*invManifest
}

// readPnpmConfig reads root's pnpm configuration. ok is false for any hook, setting or file
// the lane does not model.
func readPnpmConfig(root string) (*pnpmConfig, bool) {
	for _, f := range []string{".pnpmfile.cjs", ".pnpmfile.mjs"} {
		if _, err := os.Lstat(filepath.Join(root, f)); !absent(err) {
			return nil, false
		}
	}
	rc, ok := readOptional(filepath.Join(root, ".npmrc"))
	if !ok {
		return nil, false
	}
	for _, line := range strings.Split(string(rc), "\n") {
		k, _, _ := strings.Cut(strings.TrimSpace(line), "=")
		if k = strings.TrimSpace(k); k == "pnpmfile" || k == "global-pnpmfile" {
			return nil, false
		}
	}
	cfg := &pnpmConfig{overrides: map[string]string{}, patches: map[string]string{}, manifests: map[string]*invManifest{}}

	var data []byte
	var man struct {
		Pnpm        map[string]json.RawMessage `json:"pnpm"`
		Resolutions map[string]json.RawMessage `json:"resolutions"`
	}
	data, ok = readOptional(filepath.Join(root, "package.json"))
	if !ok || data != nil && json.Unmarshal(data, &man) != nil || len(man.Resolutions) > 0 {
		return nil, false
	}
	for k, v := range man.Pnpm {
		if !pnpmManifestKeys[k] {
			return nil, false
		}
		if k == "packageExtensions" && strings.TrimSpace(string(v)) != "{}" {
			return nil, false
		}
	}
	var manOverrides, manPatches map[string]string
	if v, ok := man.Pnpm["overrides"]; ok && json.Unmarshal(v, &manOverrides) != nil {
		return nil, false
	}
	if v, ok := man.Pnpm["patchedDependencies"]; ok && json.Unmarshal(v, &manPatches) != nil {
		return nil, false
	}

	ws, ok := readOptional(filepath.Join(root, "pnpm-workspace.yaml"))
	if !ok {
		return nil, false
	}
	var wsOverrides, wsPatches map[string]string
	var globs []string
	if ws != nil {
		docs := splitYAMLDocs(string(ws))
		if len(docs) > 1 {
			return nil, false
		}
		y := &ynode{}
		if len(docs) == 1 {
			var err error
			if y, err = parseYAMLSubset(docs[0]); err != nil {
				return nil, false
			}
		}
		for _, k := range y.keys {
			if !pnpmWorkspaceKeys[k] {
				return nil, false
			}
		}
		if wsOverrides, ok = y.child("overrides").scalars(); !ok {
			return nil, false
		}
		if wsPatches, ok = y.child("patchedDependencies").scalars(); !ok {
			return nil, false
		}
		if n := y.child("packages"); n != nil {
			if len(n.kids) > 0 || n.val != "" && n.val != "[]" {
				return nil, false
			}
			globs = n.items
		}
	}
	if len(manOverrides) > 0 && len(wsOverrides) > 0 || len(manPatches) > 0 && len(wsPatches) > 0 {
		return nil, false
	}
	maps.Copy(cfg.overrides, manOverrides)
	maps.Copy(cfg.overrides, wsOverrides)
	maps.Copy(cfg.patches, manPatches)
	maps.Copy(cfg.patches, wsPatches)

	members, ok := workspaceMembers(root, globs)
	if !ok {
		return nil, false
	}
	cfg.members = members
	for _, dir := range append([]string{"."}, members...) {
		data, ok := readOptional(filepath.Join(root, filepath.FromSlash(dir), "package.json"))
		if !ok {
			return nil, false
		}
		m := &invManifest{}
		if data != nil && json.Unmarshal(data, m) != nil {
			return nil, false
		}
		cfg.manifests[dir] = m
	}
	return cfg, true
}

// checkConfig holds the lock to the configuration: overrides and patches the lock does not
// record identically, a patch the lane cannot bound, and a manifest declaring dependencies the
// lock installs nothing for all withhold.
func (p *pnpmLock) checkConfig(cfg *pnpmConfig) bool {
	lockOverrides, ok := p.doc.child("overrides").scalars()
	if !ok || !maps.Equal(lockOverrides, cfg.overrides) {
		return false
	}
	if p.version == "5.4" && len(cfg.overrides) > 0 {
		return false
	}

	lockPatches, lkeys, ok := p.doc.child("patchedDependencies").mapping()
	if !ok || len(lockPatches) != len(cfg.patches) {
		return false
	}
	for _, k := range lkeys {
		if _, ok := cfg.patches[k]; !ok {
			return false
		}
	}
	for key, file := range cfg.patches {
		name, version := key, ""
		if n, v := splitNameAt(key); n != "" {
			name, version = n, v
		}
		if version != "" && !exactVersion(version) {
			return false
		}
		data, ok := p.readPatch(file)
		if !ok || !patchScoped(data) {
			return false
		}
		for _, e := range p.byKey {
			if e.name == name && (version == "" || e.version == version) {
				e.patched = true
			}
		}
	}
	for k, e := range p.byKey {
		if strings.Contains(k, "patch_hash=") && !e.patched {
			return false
		}
	}

	declared := func(m *invManifest) bool {
		return len(m.Dependencies)+len(m.DevDependencies)+len(m.OptionalDependencies) > 0
	}
	for dir, m := range cfg.manifests {
		if !declared(m) {
			continue
		}
		at := joinRel(p.region.prefix, dir)
		if imp := p.region.importerAt(at); imp == nil || imp.dir != at || len(imp.deps) == 0 {
			return false
		}
	}
	return true
}

// readPatch reads a patch file the configuration names, relative to the region root.
func (p *pnpmLock) readPatch(file string) ([]byte, bool) {
	if file == "" || path.IsAbs(file) || filepath.IsAbs(file) || strings.Contains(file, `\`) ||
		slices.Contains(strings.Split(file, "/"), "..") {
		return nil, false
	}
	return readInRoot(p.root, filepath.Join(p.root, filepath.FromSlash(file)), maxPatchBytes)
}

// exactVersion reports whether v is one exact semver version, not a range.
func exactVersion(v string) bool {
	if v == "" || strings.ContainsAny(v, "^~<>=|* ") || strings.EqualFold(v, "x") {
		return false
	}
	core, _, _ := strings.Cut(strings.SplitN(v, "+", 2)[0], "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, s := range parts {
		if _, err := strconv.Atoi(s); err != nil {
			return false
		}
	}
	return true
}

// patchScoped reports whether a unified diff only edits existing files whose change the lane
// can bound to the patched package: false for one that touches package.json, binding.gyp or a
// compiled addon (install behaviour), creates, deletes, renames or copies a file, carries a
// binary hunk, or does not parse.
func patchScoped(data []byte) bool {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	touches := func(p string) bool {
		base := path.Base(p)
		return base == "package.json" || base == "binding.gyp" || strings.HasSuffix(p, ".node") ||
			slices.Contains(strings.Split(p, "/"), "..")
	}
	headerPath := func(s, side string) (string, bool) {
		if i := strings.IndexByte(s, '\t'); i >= 0 {
			s = s[:i]
		}
		if s == "/dev/null" || strings.HasPrefix(s, `"`) {
			return "", false
		}
		s = strings.TrimPrefix(s, side)
		return s, s != "" && !touches(s)
	}
	files := 0
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		switch {
		case strings.HasPrefix(line, "diff --git "):
			rest := line[len("diff --git "):]
			n := (len(rest) - 5) / 2
			if strings.HasPrefix(rest, `"`) || (len(rest)-5)%2 != 0 || n <= 0 ||
				rest[:2] != "a/" || rest[2+n:5+n] != " b/" || rest[5+n:] != rest[2:2+n] || touches(rest[2:2+n]) {
				return false
			}
		case strings.HasPrefix(line, "new file mode"), strings.HasPrefix(line, "deleted file mode"),
			strings.HasPrefix(line, "rename "), strings.HasPrefix(line, "copy "),
			strings.HasPrefix(line, "GIT binary patch"), strings.HasPrefix(line, "Binary files"):
			return false
		case strings.HasPrefix(line, "--- "):
			if _, ok := headerPath(line[4:], "a/"); !ok {
				return false
			}
			if i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], "+++ ") {
				return false
			}
			if _, ok := headerPath(lines[i+1][4:], "b/"); !ok {
				return false
			}
			i++
			files++
		case strings.HasPrefix(line, "@@ "):
			oldN, newN, ok := hunkCounts(line)
			if !ok || files == 0 {
				return false
			}
			for oldN > 0 || newN > 0 {
				i++
				if i >= len(lines) {
					return false
				}
				h := lines[i]
				switch {
				case strings.HasPrefix(h, `\`):
				case strings.HasPrefix(h, "-"):
					oldN--
				case strings.HasPrefix(h, "+"):
					newN--
				case strings.HasPrefix(h, " "), h == "":
					oldN--
					newN--
				default:
					return false
				}
				if oldN < 0 || newN < 0 {
					return false
				}
			}
		}
	}
	return files > 0
}

// hunkCounts reads the old and new line counts of a "@@ -a,b +c,d @@" header.
func hunkCounts(h string) (oldN, newN int, ok bool) {
	f := strings.Fields(h)
	if len(f) < 4 || f[3] != "@@" || !strings.HasPrefix(f[1], "-") || !strings.HasPrefix(f[2], "+") {
		return 0, 0, false
	}
	count := func(s string) (int, bool) {
		start, n, has := strings.Cut(s[1:], ",")
		if _, err := strconv.Atoi(start); err != nil {
			return 0, false
		}
		if !has {
			return 1, true
		}
		c, err := strconv.Atoi(n)
		return c, err == nil && c >= 0
	}
	o, ok1 := count(f[1])
	n, ok2 := count(f[2])
	return o, n, ok1 && ok2
}
