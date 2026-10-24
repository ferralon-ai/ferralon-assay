package jsanalysis

import (
	"encoding/json"
	"maps"
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
// settings are among them: a phantom's candidates are every copy the region pins plus whatever
// Node's walk finds above the region, which covers every hoist outcome. virtualStoreDir and
// modulesDir are accepted only inside the region's node_modules (inRegionModules).
var pnpmWorkspaceKeys = map[string]bool{
	"packages": true, "catalog": true, "catalogs": true, "savePrefix": true, "updateNotifier": true,
	"ignoreScripts": true, "minimumReleaseAge": true, "verifyDepsBeforeRun": true,
	"onlyBuiltDependencies": true, "ignoredBuiltDependencies": true, "neverBuiltDependencies": true,
	// allowBuilds (pnpm 10 and later) only decides which dependency scripts run, or refuses the
	// install; it never changes the layout. Its values are not read, which is sound only because
	// the lane already treats every script as one that runs: a pnpm entry left unread is
	// scriptsUnknown and a read one with an install script is installScript, and either
	// withholds run-wide (callGraphWithDeps). A value that stops a script only narrows that.
	"allowBuilds":     true,
	"strictDepBuilds": true, "nodeLinker": true, "hoist": true, "hoistPattern": true,
	"publicHoistPattern": true, "shamefullyHoist": true, "hoistWorkspacePackages": true,
	"virtualStoreDir": true, "virtualStoreDirMaxLength": true, "modulesDir": true,
	"packageImportMethod": true, "dedupePeerDependents": true, "autoInstallPeers": true,
	"resolvePeersFromWorkspaceRoot": true, "dedupeDirectDeps": true, "overrides": true,
	"patchedDependencies": true,

	// blockExoticSubdeps (pnpm 10 and later) makes pnpm refuse an install that would resolve a
	// dependency's dependency from git or a URL; it never changes the layout pnpm installs. Only
	// the literal true or false is accepted.
	"blockExoticSubdeps": true,
}

// inRegionModules reports whether a virtualStoreDir or modulesDir setting keeps every directory
// Node's walk passes, from a stored package up to the region root, inside the region's own
// node_modules, which holds only copies the lock pins. A store elsewhere would put the walk
// through directories the lane does not model; a "$" may expand from the environment.
func inRegionModules(key, v string) bool {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	if key == "modulesDir" || key == "modules-dir" {
		return v == "node_modules"
	}
	c := path.Clean(v)
	return !strings.ContainsAny(v, `\$`) && !path.IsAbs(c) && strings.HasPrefix(c, "node_modules/")
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
	imps    map[string]*pnpmLockImporter // by build-relative directory
}

// pnpmLockImporter is one importer as pnpm's lock-against-manifest check reads it.
type pnpmLockImporter struct {
	fields     map[string]map[string]string // field, then name, then the version as locked
	specifiers map[string]string            // name to specifier, every field together
	meta       *ynode                       // dependenciesMeta
	publishDir *ynode                       // publishDirectory
}

// pnpmImporterKeys are the importer keys of the lock versions the lane reads (a 5.4 importer
// also keeps specifiers). Any other key records something the lane does not compare.
var pnpmImporterKeys = map[string]bool{
	"dependencies": true, "devDependencies": true, "optionalDependencies": true,
	"dependenciesMeta": true, "publishDirectory": true,
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
		imps: map[string]*pnpmLockImporter{},
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
		_, keys, ok := imp.mapping()
		if !ok {
			return false
		}
		if imp != p.doc {
			for _, k := range keys {
				if !pnpmImporterKeys[k] && (k != "specifiers" || p.version != "5.4") {
					return false
				}
			}
		}
		rec := &pnpmLockImporter{
			fields: map[string]map[string]string{}, specifiers: map[string]string{},
			meta: imp.child("dependenciesMeta"), publishDir: imp.child("publishDirectory"),
		}
		if p.version == "5.4" {
			s, ok := imp.child("specifiers").scalars()
			if !ok {
				return false
			}
			maps.Copy(rec.specifiers, s)
		}
		deps := map[string]*depEntry{}
		for _, g := range pnpmDepFields {
			kids, keys, ok := imp.child(g).mapping()
			if !ok {
				return false
			}
			rec.fields[g] = map[string]string{}
			for _, name := range keys {
				if deps[name] != nil {
					return false // pnpm records a name in one field only
				}
				v := kids[name].val
				if p.version != "5.4" {
					v = kids[name].child("version").str()
					if s := kids[name].child("specifier"); s != nil {
						rec.specifiers[name] = s.val
					}
				}
				t, ok := p.target(name, v)
				if !ok {
					return false
				}
				rec.fields[g][name] = v
				deps[name] = t
			}
		}
		p.imps[joinRel(p.region.prefix, dir)] = rec
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
	extras    map[string]*pnpmManifestExtra
}

// pnpmManifestExtra holds the package.json keys pnpm compares with an importer beyond the
// dependency fields.
type pnpmManifestExtra struct {
	DependenciesMeta json.RawMessage `json:"dependenciesMeta"`
	PublishConfig    json.RawMessage `json:"publishConfig"`
}

// readPnpmConfig reads root's pnpm configuration. ok is false for any hook, setting or file
// the lane does not model.
func readPnpmConfig(root string) (*pnpmConfig, bool) {
	if found, err := entryFold(root, ".pnpmfile.cjs", ".pnpmfile.mjs"); found || err != nil {
		return nil, false
	}
	if !exactCase(root, ".npmrc", "package.json", "pnpm-workspace.yaml") {
		return nil, false
	}
	rc, ok := readOptional(filepath.Join(root, ".npmrc"))
	if !ok {
		return nil, false
	}
	for _, line := range strings.Split(string(rc), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		if k = strings.TrimSpace(k); k == "pnpmfile" || k == "global-pnpmfile" {
			return nil, false
		}
		if (k == "virtual-store-dir" || k == "modules-dir") && !inRegionModules(k, v) {
			return nil, false
		}
	}
	cfg := &pnpmConfig{overrides: map[string]string{}, patches: map[string]string{}, manifests: map[string]*invManifest{}, extras: map[string]*pnpmManifestExtra{}}

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
		var body string
		if body, ok = pnpmWorkspaceBody(string(ws)); !ok {
			return nil, false
		}
		docs := splitYAMLDocs(body)
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
		// pnpm 8 and 9 read a workspace file with no keys as absent and take every package in
		// the tree as a member; pnpm 10 and later take the root alone.
		if len(y.keys) == 0 {
			return nil, false
		}
		for _, k := range y.keys {
			if !pnpmWorkspaceKeys[k] {
				return nil, false
			}
			if (k == "virtualStoreDir" || k == "modulesDir") && !inRegionModules(k, y.child(k).val) {
				return nil, false
			}
			if v := y.child(k).val; k == "blockExoticSubdeps" && v != "true" && v != "false" {
				return nil, false
			}
		}
		if wsOverrides, ok = y.child("overrides").scalars(); !ok {
			return nil, false
		}
		if _, ok = y.child("allowBuilds").scalars(); !ok {
			return nil, false
		}
		if wsPatches, ok = y.child("patchedDependencies").scalars(); !ok {
			return nil, false
		}
		if n := y.child("packages"); n != nil {
			if len(n.kids) > 0 || n.val != "" && n.val != "[]" || n.val == "" && len(n.items) == 0 {
				return nil, false // a null packages errors on pnpm 8 and 9 and is root-only on 10+
			}
			// pnpm always takes the region root as a project, so an entry that is exactly "."
			// selects nothing more on any version and is dropped. Every other dot form still
			// goes to workspaceMembers and withholds. yarn classic links the root into its own
			// node_modules for a ".", so readYarnClassic keeps withholding it.
			globs = slices.DeleteFunc(slices.Clone(n.items), func(g string) bool { return g == "." })
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
	if pnpmAltManifestIn(root) {
		return nil, false
	}
	for _, dir := range append([]string{"."}, members...) {
		data, ok := readOptional(filepath.Join(root, filepath.FromSlash(dir), "package.json"))
		if !ok {
			return nil, false
		}
		m, x := &invManifest{}, &pnpmManifestExtra{}
		if data != nil && (json.Unmarshal(data, m) != nil || json.Unmarshal(data, x) != nil) {
			return nil, false
		}
		cfg.manifests[dir], cfg.extras[dir] = m, x
	}
	return cfg, true
}

// pnpmWorkspaceBody returns the one document of a pnpm-workspace.yaml stream. pnpm loads the
// file as a single document: a block of blank and comment lines ahead of one "---" is not a
// document, while content before the marker, a second marker or a trailing one is an error on
// every version. ok is false for any marker but one line exactly "---" whose preceding lines are
// all spaces and an optional comment free of tabs, CRs and BOMs. What is left still has to hold
// keys: a prefix with nothing after the marker is not read as a file with no keys.
// splitYAMLDocs stays as it is; the lock reader needs its two-document split.
func pnpmWorkspaceBody(s string) (string, bool) {
	lines := strings.Split(s, "\n")
	sep := -1
	for i, l := range lines {
		if t := strings.TrimRight(l, " \t\r"); t == "---" || strings.HasPrefix(t, "--- ") {
			if sep >= 0 || l != "---" {
				return "", false
			}
			sep = i
		}
	}
	if sep < 0 {
		return s, true
	}
	for _, l := range lines[:sep] {
		if t := strings.TrimLeft(l, " "); t != "" && (t[0] != '#' || strings.ContainsAny(t, "\t\r\uFEFF")) {
			return "", false
		}
	}
	return strings.Join(lines[sep+1:], "\n"), true
}

// pnpmAltManifestIn reports whether root holds a pnpmAltManifests file in any case, or cannot
// be read. Members are held to the same by memberManifest.
func pnpmAltManifestIn(root string) bool {
	found, err := entryFold(root, pnpmAltManifests...)
	return found || err != nil
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

	for dir, m := range cfg.manifests {
		if barePeer(m) {
			return false
		}
		at := joinRel(p.region.prefix, dir)
		if imp := p.region.importerAt(at); imp == nil || imp.dir != at || !p.imps[at].satisfies(m, cfg.extras[dir]) {
			return false
		}
	}
	return true
}

// pnpmDepFields are the fields pnpm installs from, in the order it takes a name declared in
// several: optionalDependencies, then dependencies, then devDependencies.
var pnpmDepFields = []string{"optionalDependencies", "dependencies", "devDependencies"}

// pnpmInstallFields returns the names and specifiers pnpm records under each field for a manifest
// declaring optional, deps and dev. A name declared in several fields is recorded only in the
// first of pnpmDepFields whose specifier is non-empty: pnpm tests the earlier fields by the
// specifier's truthiness, so an empty one does not claim the name.
func pnpmInstallFields(optional, deps, dev map[string]string) map[string]map[string]string {
	out := map[string]map[string]string{"optionalDependencies": {}, "dependencies": {}, "devDependencies": {}}
	maps.Copy(out["optionalDependencies"], optional)
	for n, spec := range deps {
		if optional[n] == "" {
			out["dependencies"][n] = spec
		}
	}
	for n, spec := range dev {
		if optional[n] == "" && deps[n] == "" {
			out["devDependencies"][n] = spec
		}
	}
	return out
}

// satisfies reports whether pnpm takes r as up to date with the manifest m (and x): the check
// satisfiesPackageManifest in pnpm's lockfile/lockfile-utils (pnpm 8) and lockfile/verification
// (pnpm 9 to 11), at its strictest across those versions. Otherwise a frozen install refuses,
// and any other install re-resolves from the manifest, so what the lock pins is not what the
// build installs. Each clause is pnpm's:
//
//   - the specifiers, every field together, equal the manifest's (dev, then dependencies, then
//     optional overriding), compared exactly (pnpm 11 also equates spellings of one git URL);
//   - publishDirectory equals publishConfig.directory, both absent or the same string;
//   - dependenciesMeta is equal, absent reading as empty;
//   - each field holds exactly the names pnpmInstallFields assigns it (pnpm also compares each
//     with its specifier, which the flat comparison already decides; it counts them, and with
//     excludeLinksFromLockfile also accepts the count of non-linked entries; the lane does not);
//   - each locked release version satisfies its specifier where the specifier is a semver range
//     (pnpm 10 and 11).
//
// pnpm compares a peer only under auto-install-peers; barePeer withholds those manifests first.
func (r *pnpmLockImporter) satisfies(m *invManifest, x *pnpmManifestExtra) bool {
	if r == nil || x == nil {
		return false
	}
	all := maps.Clone(m.DevDependencies)
	if all == nil {
		all = map[string]string{}
	}
	maps.Copy(all, m.Dependencies)
	maps.Copy(all, m.OptionalDependencies)
	if !maps.Equal(r.specifiers, all) {
		return false
	}
	if !pnpmPublishDirEqual(r.publishDir, x.PublishConfig) {
		return false
	}
	if !pnpmMetaEqual(r.meta, x.DependenciesMeta) {
		return false
	}
	fields := pnpmInstallFields(m.OptionalDependencies, m.Dependencies, m.DevDependencies)
	for _, f := range pnpmDepFields {
		if len(r.fields[f]) != len(fields[f]) {
			return false
		}
		for name, spec := range fields[f] {
			v, ok := r.fields[f][name]
			if !ok || !pnpmVersionInRange(v, spec) {
				return false
			}
		}
	}
	return true
}

// pnpmVersionInRange applies pnpm's broken-resolution clause: a locked version that is a semver
// release must satisfy a specifier that is a semver range. A version carrying a peer suffix is
// compared without it. A version or specifier with ':', '/' or '@' (link:, file:, workspace:,
// npm:, git, an alias) is no semver, so pnpm skips it. A version equal to its specifier satisfies
// it, a prerelease included. rangeSatisfied fails closed on any other form it does not model, a
// dist-tag included, which pnpm would skip.
func pnpmVersionInRange(version, spec string) bool {
	version, _, _ = strings.Cut(version, "(")
	if version == spec || strings.ContainsAny(version, ":/@") || strings.ContainsAny(spec, ":/") {
		return true
	}
	return rangeSatisfied(version, spec)
}

// pnpmPublishDirEqual compares an importer's publishDirectory with a manifest's publishConfig.
// Either side present must be a string; pnpm compares with !==, so null and absent differ.
func pnpmPublishDirEqual(lock *ynode, publishConfig json.RawMessage) bool {
	var lockDir *string
	if lock != nil {
		if !yamlString(lock) {
			return false
		}
		lockDir = &lock.val
	}
	var manDir *string
	if len(publishConfig) > 0 && string(publishConfig) != "null" {
		var pc map[string]json.RawMessage
		if json.Unmarshal(publishConfig, &pc) != nil || pc == nil {
			return false
		}
		if d, ok := pc["directory"]; ok {
			var s string
			if json.Unmarshal(d, &s) != nil || string(d) == "null" {
				return false
			}
			manDir = &s
		}
	}
	return lockDir == nil && manDir == nil || lockDir != nil && manDir != nil && *lockDir == *manDir
}

// pnpmMetaEqual compares an importer's dependenciesMeta with a manifest's, each read as name to
// injected ("true", "false", or "" for an empty object). Any other shape, or another key, is
// not read.
func pnpmMetaEqual(lock *ynode, manifest json.RawMessage) bool {
	got := map[string]string{}
	if lock != nil && !(lock.val == "" && len(lock.kids) == 0) {
		kids, keys, ok := lock.mapping()
		if !ok {
			return false
		}
		for _, name := range keys {
			c := kids[name]
			ck, ckeys, ok := c.mapping()
			if !ok || len(ckeys) == 0 && c.val != "{}" || len(ckeys) > 1 {
				return false
			}
			got[name] = ""
			if len(ckeys) == 1 {
				v := ck[ckeys[0]]
				if ckeys[0] != "injected" || v.quoted || len(v.kids) > 0 || v.val != "true" && v.val != "false" {
					return false
				}
				got[name] = v.val
			}
		}
	}
	want := map[string]string{}
	if len(manifest) > 0 && string(manifest) != "null" {
		var m map[string]map[string]json.RawMessage
		if json.Unmarshal(manifest, &m) != nil {
			return false
		}
		for name, o := range m {
			if o == nil || len(o) > 1 {
				return false
			}
			want[name] = ""
			for k, v := range o {
				if k != "injected" || string(v) != "true" && string(v) != "false" {
					return false
				}
				want[name] = string(v)
			}
		}
	}
	return maps.Equal(got, want)
}

// yamlString reports whether n is a string scalar to a YAML loader: quoted, or plain text that
// no schema reads as null, a boolean or a number. It fails closed on plain text it is unsure of.
func yamlString(n *ynode) bool {
	if len(n.kids) > 0 || len(n.items) > 0 {
		return false
	}
	if n.quoted {
		return true
	}
	v := n.val
	if v == "" || strings.ContainsAny(v[:1], "{[") {
		return false
	}
	switch strings.ToLower(v) {
	case "null", "~", "true", "false", "yes", "no", "on", "off", "y", "n":
		return false
	}
	c := v[0]
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '/' || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../")
}

// barePeer reports whether m declares a peer dependency it does not also declare in a field
// pnpm installs from. pnpm 8 and later install such a peer by default (auto-install-peers) and
// pnpm 7 does not; the lane does not model which applies, so the configuration is not read.
func barePeer(m *invManifest) bool {
	for name := range m.PeerDependencies {
		if _, ok := m.Dependencies[name]; ok {
			continue
		}
		if _, ok := m.DevDependencies[name]; ok {
			continue
		}
		if _, ok := m.OptionalDependencies[name]; !ok {
			return true
		}
	}
	return false
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
// compiled addon (install behaviour), names an absolute path, creates, deletes, renames or copies
// a file, changes a file's mode, carries a binary hunk, or does not parse.
func patchScoped(data []byte) bool {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	touches := func(p string) bool {
		base := path.Base(p)
		return strings.EqualFold(base, "package.json") || strings.EqualFold(base, "binding.gyp") ||
			strings.HasSuffix(strings.ToLower(p), ".node") || strings.HasPrefix(p, "/") ||
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
			strings.HasPrefix(line, "old mode"), strings.HasPrefix(line, "new mode"),
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
