package jsanalysis

// loadset.go computes the runtime load set: the installed npm package instances that
// first-party runtime code can load. It is the evidence behind the package_not_loaded
// refutation (ne-gate-contract §5, arm B): a package installed at the admitted version that
// no runtime-loaded module can reach.
//
// The set is an over-approximation by construction. Every uncertain step either adds
// instances (never removes them) or marks the result incomplete, and an incomplete result
// never refutes:
//
//   - Install model: npm lockfile v2/v3 `packages` entries (engine L), or the installed
//     node_modules tree (engine D) when the lockfile carries no per-instance edges (npm v1,
//     yarn, pnpm, or two dialects at one root). A root with neither is incomplete.
//   - Roots: bare specifiers in first-party runtime source (require, import, import(),
//     require.resolve, re-export), string literals naming an installed package, JSX/SFC
//     runtimes, Node preload flags (-r/--require/--import/--loader) and a curated table of
//     bins that run application code in-process. Other script bins and dev-tooling files are
//     not roots (Eric's standing decision); they are tracked separately only to label the
//     refutation detail.
//   - Closure: dependencies, optional and peer edges, resolved by Node's node_modules walk
//     from the loading instance, so a hoisted copy and a nested copy are distinct instances.
//   - Build configs (webpack, vite, babel, ...): a package a build config names is bundled,
//     and the bundler resolves its imports, declared or not, by the node_modules walk. It
//     brings its dependency closure plus every package that walk can see from its install
//     path (in practice the hoisted top level), transitively. A walk that leaves the build
//     dir declares uninspectable_package.
//   - Build injectors (babel helpers, tslib, bundler polyfills) are loaded whenever their
//     injector is installed in the same lock root, because they land in runtime output
//     without a first-party import.
//   - Enumerating loaders (packages that load others by a name chosen in first-party code or
//     config: view engines, SQL clients, babel/webpack plugins) add their curated targets, or
//     emit an unbounded ScopedReason that blocks refutation.
//
// Not being in the load set is necessary but not sufficient. A package also has to sit outside
// the runtime install closure (class (i)): every instance at the admitted version carries its
// lockfile's dev marker and is unreachable over dependencies/optionalDependencies/
// peerDependencies from every first-party manifest and lockfile workspace entry. A package a
// production install puts on disk (class (ii)) never refutes, because code we cannot see (a
// dependency's soft import, a dynamic require) could load it. Class (i) assumes dev/tooling
// groups are not installed at runtime, so the refutation is withheld whenever the repo shows a
// deploy-path install that keeps them (prodinstall.go), the lockfile a root selected carries
// no dev markers (yarn, pnpm, or an ambiguous dialect), or the install closure resolves outside
// the build dir.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// pkgInstance is one installed copy of a package, keyed by its build-relative install path.
type pkgInstance struct {
	path     string // slash-separated, build-relative: "node_modules/a", "web/node_modules/b/node_modules/c"
	dirName  string // install-dir name (the specifier that resolves to it; differs from name for aliases)
	name     string // package identity
	version  string
	deps     []string // install-dir names
	optional []string
	peers    []string
	bins     []string
	root     string // owning lock root, build-relative ("" = build dir)
}

// installSeed is one runtime-dependency edge of a first-party manifest or lockfile workspace
// entry: the install-dir name it resolves and the directory it resolves from.
type installSeed struct {
	dir  string
	from string
}

// linkExternal marks a link whose target lies outside the build dir.
const linkExternal = "\x00external"

type installModel struct {
	buildReal string
	roots     []string // build-relative lock roots, deepest last
	inst      map[string]*pkgInstance
	links     map[string]string // install path -> build-relative target dir, or linkExternal
	byDir     map[string][]*pkgInstance
	byName    map[string][]*pkgInstance
	byBin     map[string][]*pkgInstance
	sorted    []string
	devMarks  map[string]string // install path -> version, for lockfile entries marked dev-only
	seeds     []installSeed     // runtime-dependency edges of lockfile root/workspace entries
	ownNames  []string          // names of lockfile root/workspace entries (first-party packages)
}

type resolveKind int

const (
	resolvedNone resolveKind = iota
	resolvedInstance
	resolvedFirstParty
	resolvedExternal
)

// loadSet is the computed runtime load set plus what the refutation detail reports.
type loadSet struct {
	model     *installModel
	complete  bool
	gaps      []string
	loaded    map[string]bool   // install paths with code loaded at runtime
	selfOnly  map[string]bool   // loaded paths whose dependency closure was not taken (bundler runtimes)
	roots     map[string]string // package name -> first-party reference that rooted it
	loaders   map[string]bool
	injectors map[string]bool
	devFrom   map[string]string // install path -> dev-tooling root label that reaches it
	scoped    []plugin.ScopedReason
	installed map[string]bool // install paths in the runtime install closure
	ownNames  map[string]bool // canonical names of the project's own packages (root and workspaces)
	// noDevOnly says why no package counts as outside the runtime install closure ("" = class
	// (i) is decidable for this build).
	noDevOnly string
}

func (ls *loadSet) gap(format string, args ...any) {
	ls.complete = false
	if len(ls.gaps) < 16 {
		ls.gaps = append(ls.gaps, fmt.Sprintf(format, args...))
	}
}

// computeLoadSet builds the install model for buildDir and closes the runtime roots over it.
func computeLoadSet(buildDir string) *loadSet {
	ls := &loadSet{
		complete:  true,
		loaded:    map[string]bool{},
		selfOnly:  map[string]bool{},
		roots:     map[string]string{},
		loaders:   map[string]bool{},
		injectors: map[string]bool{},
		devFrom:   map[string]string{},
	}
	m, err := buildInstallModel(buildDir, ls)
	if err != nil {
		ls.gap("build dir unreadable: %v", err)
		return ls
	}
	ls.model = m

	fp := scanFirstParty(m, ls)
	c := &closer{ls: ls, m: m}
	for _, r := range fp.runtime {
		c.addRoot(r)
	}
	c.drain()
	rc := &closer{ls: ls, m: m, reach: map[string]bool{}}
	for _, r := range fp.config {
		rc.addRoot(r)
	}
	c.applyInjectors()
	c.applyLoaders()

	dc := &closer{ls: ls, m: m, dev: true}
	for _, r := range fp.dev {
		dc.addRoot(r)
	}
	dc.drain()

	ls.ownNames = map[string]bool{}
	for _, n := range append(m.ownNames, fp.names...) {
		ls.ownNames[canonicalNpmName(n)] = true
	}
	ls.installed, ls.noDevOnly = m.installClosure(append(m.seeds, fp.install...))
	if ls.noDevOnly == "" {
		ls.noDevOnly = prodInstallKeepsDev(m.buildReal)
	}
	return ls
}

// installClosure is the set of install paths a production install puts on disk: the
// dependencies, optionalDependencies and peerDependencies of every first-party manifest and
// lockfile workspace entry, closed over the installed instances' own edges. An edge that does
// not resolve adds every instance with that install-dir name. A non-empty reason (an edge
// resolving outside the build dir) means the closure is unknown.
func (m *installModel) installClosure(seeds []installSeed) (map[string]bool, string) {
	in := map[string]bool{}
	var queue []*pkgInstance
	why := ""
	add := func(from, dir string) {
		var hits []*pkgInstance
		switch kind, inst := m.resolve(from, dir); kind {
		case resolvedInstance:
			hits = []*pkgInstance{inst}
		case resolvedExternal:
			if why == "" {
				why = dir + " resolves outside the build dir"
			}
		case resolvedNone:
			hits = m.byDir[dir]
		}
		for _, h := range hits {
			if !in[h.path] {
				in[h.path] = true
				queue = append(queue, h)
			}
		}
	}
	for _, s := range seeds {
		add(s.from, s.dir)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, names := range [][]string{cur.deps, cur.optional, cur.peers} {
			for _, d := range names {
				add(cur.path, d)
			}
		}
	}
	return in, why
}

// devOnly reports whether instance in is outside the runtime install closure (class (i)).
func (ls *loadSet) devOnly(in *pkgInstance) bool {
	if ls.noDevOnly != "" || ls.installed[in.path] {
		return false
	}
	v, ok := ls.model.devMarks[in.path]
	return ok && v == in.version
}

// rootRef is one first-party reference to a package: the specifier as written, the
// build-relative directory it resolves from, and a label naming its source for the detail.
type rootRef struct {
	spec  string
	from  string
	label string
	// fallback: when the specifier does not resolve from `from`, load every installed
	// instance with that install-dir name instead (over-approximation, never a refutation).
	fallback bool
}

// --- install model -------------------------------------------------------------------

func buildInstallModel(buildDir string, ls *loadSet) (*installModel, error) {
	real, err := filepath.EvalSymlinks(buildDir)
	if err != nil {
		return nil, err
	}
	m := &installModel{
		buildReal: real,
		inst:      map[string]*pkgInstance{},
		links:     map[string]string{},
		byDir:     map[string][]*pkgInstance{},
		byName:    map[string][]*pkgInstance{},
		byBin:     map[string][]*pkgInstance{},
		devMarks:  map[string]string{},
	}
	absRoots := discoverProjectRoots(real)
	if len(absRoots) == 0 {
		ls.gap("no package.json or lockfile")
		return m, nil
	}
	for _, ar := range absRoots {
		m.roots = append(m.roots, m.rel(ar))
	}
	sort.Slice(m.roots, func(i, j int) bool { return len(m.roots[i]) < len(m.roots[j]) })

	for _, ar := range absRoots {
		rel := m.rel(ar)
		label := rel
		if label == "" {
			label = "."
		}
		sel, part := selectLockfile(ar)
		if !part.Complete && containsReason(part.Reasons, plugin.PartialReasonNoManifest) {
			ls.gap("%s: no lockfile", label)
			continue
		}
		if part.Complete && sel.dialect == "npm" && m.loadNpmLock(sel.path, rel, ls) {
			continue
		}
		nm := filepath.Join(ar, "node_modules")
		if fi, err := os.Stat(nm); err == nil && fi.IsDir() {
			m.loadDisk(ar, ls)
			// Dev markers come only from the lockfile the root selected. A yarn or pnpm root,
			// or one whose lockfile dialect is ambiguous, cannot tell dev from runtime, so
			// nothing in it refutes.
			if part.Complete && sel.dialect == "npm" {
				m.readDevMarks(sel.path, rel)
			}
			continue
		}
		why := "lockfile carries no per-instance edges"
		if !part.Complete {
			why = "lockfile dialect ambiguous"
		}
		ls.gap("%s: %s and node_modules is not installed", label, why)
	}
	for _, idx := range []map[string][]*pkgInstance{m.byDir, m.byName, m.byBin} {
		for _, list := range idx {
			sort.Slice(list, func(i, j int) bool { return list[i].path < list[j].path })
		}
	}
	return m, nil
}

// add registers an instance and indexes it.
func (m *installModel) add(in *pkgInstance) {
	m.inst[in.path] = in
	m.byDir[in.dirName] = append(m.byDir[in.dirName], in)
	key := canonicalNpmName(in.name)
	m.byName[key] = append(m.byName[key], in)
	for _, b := range in.bins {
		m.byBin[b] = append(m.byBin[b], in)
	}
	m.sorted = nil
}

// sortedPaths returns every install path in order (cached until the next add).
func (m *installModel) sortedPaths() []string {
	if m.sorted == nil {
		m.sorted = make([]string, 0, len(m.inst))
		for p := range m.inst {
			m.sorted = append(m.sorted, p)
		}
		sort.Strings(m.sorted)
	}
	return m.sorted
}

func containsReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

// rel returns abs relative to the build dir, slash-separated; "" for the build dir itself.
func (m *installModel) rel(abs string) string {
	r, err := filepath.Rel(m.buildReal, abs)
	if err != nil || r == "." {
		return ""
	}
	return filepath.ToSlash(r)
}

func (m *installModel) inside(rel string) bool {
	return rel != ".." && !strings.HasPrefix(rel, "../")
}

func (m *installModel) ownerRoot(p string) string {
	owner := ""
	for _, r := range m.roots {
		if r == "" || p == r || strings.HasPrefix(p, r+"/") {
			if len(r) >= len(owner) {
				owner = r
			}
		}
	}
	return owner
}

type npmLoadPkg struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Bin                  json.RawMessage   `json:"bin"`
	Dev                  bool              `json:"dev"`
}

// loadNpmLock loads an npm v2/v3 lockfile's `packages` map. It returns false when the
// lockfile has no `packages` map (v1), leaving the root to the disk engine.
func (m *installModel) loadNpmLock(lockPath, root string, ls *loadSet) bool {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		ls.gap("%s: unreadable", m.rel(lockPath))
		return true
	}
	var lock struct {
		LockfileVersion int                   `json:"lockfileVersion"`
		Packages        map[string]npmLoadPkg `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		ls.gap("%s: unparseable", m.rel(lockPath))
		return true
	}
	if lock.LockfileVersion < 2 || len(lock.Packages) == 0 {
		return false
	}
	count, edges := 0, 0
	for key, p := range lock.Packages {
		if key == "" || !isInstallPath(key) {
			// The root project or a workspace member: first-party code, scanned as source.
			edges += len(p.Dependencies) + len(p.OptionalDependencies) + len(p.PeerDependencies)
			if !p.Link {
				m.seeds = append(m.seeds, runtimeSeeds(p, joinRel(root, key))...)
			}
			if p.Name != "" {
				m.ownNames = append(m.ownNames, p.Name)
			}
			continue
		}
		ip := joinRel(root, key)
		if p.Dev {
			m.devMarks[ip] = p.Version
		}
		if p.Link {
			m.links[ip] = m.linkTarget(joinRel(root, p.Resolved))
			continue
		}
		dir := npmName(key, "")
		name := p.Name
		if name == "" {
			name = dir
		}
		in := &pkgInstance{
			path: ip, dirName: dir, name: name, version: p.Version,
			deps: sortedKeysOf(p.Dependencies), optional: sortedKeysOf(p.OptionalDependencies),
			peers: sortedKeysOf(p.PeerDependencies), bins: binNames(p.Bin, name), root: root,
		}
		m.add(in)
		count++
		edges += len(in.deps) + len(in.optional) + len(in.peers)
	}
	if count >= 2 && edges == 0 {
		ls.gap("%s: lockfile lists %d packages and no dependency edges", m.rel(lockPath), count)
	}
	return true
}

// runtimeSeeds lists a manifest's production-install edges, resolved from dir.
func runtimeSeeds(p npmLoadPkg, dir string) []installSeed {
	var out []installSeed
	for _, mp := range []map[string]string{p.Dependencies, p.OptionalDependencies, p.PeerDependencies} {
		for _, d := range sortedKeysOf(mp) {
			out = append(out, installSeed{dir: d, from: dir})
		}
	}
	return out
}

// readDevMarks records the dev markers of the npm lockfile a disk-engine root selected: v2/v3
// `packages` entries by install path, or the v1 nested `dependencies` tree, whose nesting mirrors
// node_modules. The caller never passes a lockfile the root did not select, so a yarn or pnpm
// root records none and nothing in it is class (i).
func (m *installModel) readDevMarks(lockPath, root string) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return
	}
	var lock struct {
		Packages     map[string]npmLoadPkg `json:"packages"`
		Dependencies map[string]v1LockDep  `json:"dependencies"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return
	}
	if len(lock.Packages) > 0 {
		for key, p := range lock.Packages {
			if p.Dev && isInstallPath(key) {
				m.devMarks[joinRel(root, key)] = p.Version
			}
		}
		return
	}
	m.walkV1Marks(lock.Dependencies, root)
}

type v1LockDep struct {
	Version      string               `json:"version"`
	Dev          bool                 `json:"dev"`
	Dependencies map[string]v1LockDep `json:"dependencies"`
}

func (m *installModel) walkV1Marks(deps map[string]v1LockDep, parent string) {
	for name, d := range deps {
		ip := joinRel(parent, "node_modules/"+name)
		if d.Dev {
			m.devMarks[ip] = d.Version
		}
		m.walkV1Marks(d.Dependencies, ip)
	}
}

// linkTarget normalizes a build-relative link target, marking targets outside the build dir.
func (m *installModel) linkTarget(rel string) string {
	rel = path.Clean(rel)
	if rel == "." {
		return ""
	}
	if !m.inside(rel) {
		return linkExternal
	}
	return rel
}

func isInstallPath(key string) bool {
	return strings.HasPrefix(key, "node_modules/") || strings.Contains(key, "/node_modules/")
}

func joinRel(a, b string) string {
	if a == "" {
		return path.Clean(b)
	}
	return path.Clean(a + "/" + b)
}

// loadDisk indexes every installed package under root's node_modules trees (including
// workspace members' own node_modules and pnpm's virtual store), without following links.
func (m *installModel) loadDisk(absRoot string, ls *loadSet) {
	_ = filepath.WalkDir(absRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree is indexed as absent.
		}
		if d.Name() == "node_modules" {
			m.walkNodeModules(p, ls)
			return filepath.SkipDir
		}
		if p != absRoot && skipDir(d.Name()) {
			return filepath.SkipDir
		}
		return nil
	})
}

func (m *installModel) walkNodeModules(absNM string, ls *loadSet) {
	entries, err := os.ReadDir(absNM)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		abs := filepath.Join(absNM, name)
		switch {
		case name == ".pnpm":
			store, _ := os.ReadDir(abs)
			for _, s := range store {
				if s.IsDir() {
					m.walkNodeModules(filepath.Join(abs, s.Name(), "node_modules"), ls)
				}
			}
		case strings.HasPrefix(name, "."):
		case strings.HasPrefix(name, "@") && e.IsDir():
			scoped, _ := os.ReadDir(abs)
			for _, s := range scoped {
				m.indexDiskEntry(filepath.Join(abs, s.Name()), s, ls)
			}
		default:
			m.indexDiskEntry(abs, e, ls)
		}
	}
}

func (m *installModel) indexDiskEntry(abs string, e os.DirEntry, ls *loadSet) {
	rel := m.rel(abs)
	if e.Type()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return // dangling link: nothing installed there
		}
		m.links[rel] = m.linkTarget(m.rel(target))
		return
	}
	if !e.IsDir() {
		return
	}
	if m.indexDiskPackage(rel) == nil {
		return
	}
	m.walkNodeModules(filepath.Join(abs, "node_modules"), ls)
}

// indexDiskPackage reads the package.json installed at build-relative dir rel.
func (m *installModel) indexDiskPackage(rel string) *pkgInstance {
	if in, ok := m.inst[rel]; ok {
		return in
	}
	data, err := os.ReadFile(filepath.Join(m.buildReal, filepath.FromSlash(rel), "package.json"))
	if err != nil {
		return nil
	}
	var p npmLoadPkg
	if json.Unmarshal(data, &p) != nil {
		return nil
	}
	dir := npmName(rel, "")
	name := p.Name
	if name == "" {
		name = dir
	}
	in := &pkgInstance{
		path: rel, dirName: dir, name: name, version: p.Version,
		deps: sortedKeysOf(p.Dependencies), optional: sortedKeysOf(p.OptionalDependencies),
		peers: sortedKeysOf(p.PeerDependencies), bins: binNames(p.Bin, name), root: m.ownerRoot(rel),
	}
	m.add(in)
	return in
}

func sortedKeysOf(mp map[string]string) []string {
	out := make([]string, 0, len(mp))
	for k := range mp {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// binNames reads a manifest `bin` field: a string (named after the package) or a map.
func binNames(raw json.RawMessage, name string) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s == "" {
			return nil
		}
		if i := strings.LastIndexByte(name, '/'); i >= 0 {
			return []string{name[i+1:]}
		}
		return []string{name}
	}
	var mp map[string]string
	if json.Unmarshal(raw, &mp) == nil {
		return sortedKeysOf(mp)
	}
	return nil
}

// resolve applies Node's node_modules walk for the package `dir` from build-relative
// directory `from`, following links.
func (m *installModel) resolve(from, dir string) (resolveKind, *pkgInstance) {
	d := from
	for {
		cand := "node_modules/" + dir
		if d != "" {
			cand = d + "/node_modules/" + dir
		}
		if in, ok := m.inst[cand]; ok {
			return resolvedInstance, in
		}
		if t, ok := m.links[cand]; ok {
			return m.followLink(t)
		}
		if d == "" {
			return resolvedNone, nil
		}
		d = parentDir(d)
	}
}

func (m *installModel) followLink(target string) (resolveKind, *pkgInstance) {
	if target == linkExternal {
		return resolvedExternal, nil
	}
	if !isInstallPath(target) {
		return resolvedFirstParty, nil
	}
	if in := m.indexDiskPackage(target); in != nil {
		return resolvedInstance, in
	}
	return resolvedNone, nil
}

func parentDir(d string) string {
	if i := strings.LastIndexByte(d, '/'); i >= 0 {
		return d[:i]
	}
	return ""
}

// --- closure -------------------------------------------------------------------------

type closer struct {
	ls    *loadSet
	m     *installModel
	dev   bool
	queue []*pkgInstance
	label string
	// reach, when non-nil, makes this the build-config closer: a package a build config names
	// is bundled, and a bundler resolves the package's imports, declared or not, by the same
	// node_modules walk Node uses. Every instance it adds brings its dependency closure plus
	// every package that walk can see from its install path (in practice the hoisted top
	// level), transitively. reach records the instances already expanded that way.
	reach map[string]bool
	// walked records the node_modules directories the build-config closer has added.
	walked map[string]bool
}

func (c *closer) seen(in *pkgInstance) bool {
	if c.reach != nil {
		return c.reach[in.path]
	}
	if c.dev {
		_, ok := c.ls.devFrom[in.path]
		return ok || c.ls.loaded[in.path]
	}
	return c.ls.loaded[in.path] && !c.ls.selfOnly[in.path]
}

func (c *closer) add(in *pkgInstance) {
	if c.seen(in) {
		return
	}
	if c.reach != nil {
		c.reach[in.path] = true
	}
	if c.dev {
		c.ls.devFrom[in.path] = c.label
	} else {
		c.ls.loaded[in.path] = true
		delete(c.ls.selfOnly, in.path)
	}
	c.queue = append(c.queue, in)
}

func (c *closer) addRoot(r rootRef) {
	dir, _ := splitBareSpecifier(r.spec)
	c.label = r.label
	switch kind, in := c.m.resolve(r.from, dir); kind {
	case resolvedInstance:
		if !c.dev {
			if _, ok := c.ls.roots[in.name]; !ok {
				c.ls.roots[in.name] = r.label
			}
		}
		c.add(in)
	case resolvedExternal:
		if !c.dev {
			c.ls.gap("%s resolves outside the build dir (%s)", dir, r.label)
		}
	case resolvedNone:
		if !r.fallback {
			return
		}
		for _, in := range c.m.byDir[dir] {
			if !c.dev {
				if _, ok := c.ls.roots[in.name]; !ok {
					c.ls.roots[in.name] = r.label
				}
			}
			c.add(in)
		}
	}
	c.drain()
}

func (c *closer) drain() {
	for len(c.queue) > 0 {
		in := c.queue[0]
		c.queue = c.queue[1:]
		if c.dev {
			c.label = c.ls.devFrom[in.path]
		}
		c.edges(in, in.deps, true)
		c.edges(in, in.optional, false)
		c.edges(in, in.peers, false)
		if c.reach != nil {
			c.visible(in)
		}
	}
}

// visible adds every package the node_modules walk can resolve from in's install path: each
// package directly inside a node_modules directory at that path or any ancestor in the build dir.
func (c *closer) visible(in *pkgInstance) {
	if c.walked == nil {
		c.walked = map[string]bool{}
	}
	for d := in.path; ; d = parentDir(d) {
		nm := "node_modules"
		if d != "" {
			nm = d + "/node_modules"
		}
		if !c.walked[nm] {
			c.walked[nm] = true
			for _, child := range c.m.nodeModulesChildren(nm) {
				c.add(child)
			}
			for _, t := range c.m.nodeModulesLinks(nm) {
				switch kind, child := c.m.followLink(t); kind {
				case resolvedInstance:
					c.add(child)
				case resolvedExternal:
					c.uninspectable(in)
				}
			}
		}
		if d == "" {
			return
		}
	}
}

// uninspectable declares that the build-config reach of in cannot be enumerated: a link on its
// resolution path leaves the build dir. The declaration names no targets, so it withholds every
// refutation.
func (c *closer) uninspectable(in *pkgInstance) {
	purl := "pkg:npm/" + in.name
	for _, s := range c.ls.scoped {
		if s.Reason == plugin.PartialReasonUninspectablePackage && s.Package == purl {
			return
		}
	}
	c.ls.scoped = append(c.ls.scoped, plugin.ScopedReason{Reason: plugin.PartialReasonUninspectablePackage, Package: purl})
}

// nodeModulesDir returns the node_modules directory an install path sits directly inside.
func nodeModulesDir(ip string) string {
	i := strings.LastIndex(ip, "node_modules/")
	if i < 0 {
		return ""
	}
	return ip[:i+len("node_modules")]
}

// nodeModulesChildren returns the instances directly inside node_modules directory nm.
func (m *installModel) nodeModulesChildren(nm string) []*pkgInstance {
	var out []*pkgInstance
	for _, p := range m.sortedPaths() {
		if nodeModulesDir(p) == nm {
			out = append(out, m.inst[p])
		}
	}
	return out
}

// nodeModulesLinks returns the targets of the install links directly inside nm.
func (m *installModel) nodeModulesLinks(nm string) []string {
	var out []string
	for _, ip := range sortedKeysOf(m.links) {
		if nodeModulesDir(ip) == nm {
			out = append(out, m.links[ip])
		}
	}
	return out
}

func (c *closer) edges(in *pkgInstance, names []string, required bool) {
	for _, dep := range names {
		kind, child := c.m.resolve(in.path, dep)
		switch kind {
		case resolvedInstance:
			c.add(child)
		case resolvedExternal:
			if !c.dev {
				c.ls.gap("%s (dependency of %s) resolves outside the build dir", dep, in.name)
			}
			if c.reach != nil {
				c.uninspectable(in)
			}
		case resolvedNone:
			if !required {
				continue
			}
			alts := c.m.byDir[dep]
			if len(alts) == 0 && !c.dev && !isNodeBuiltin(dep) {
				c.ls.gap("%s@%s depends on %s, which is not installed", in.name, in.version, dep)
			}
			for _, a := range alts {
				c.add(a)
			}
		}
	}
}

func (c *closer) selfLoad(in *pkgInstance) {
	if c.ls.loaded[in.path] {
		return
	}
	c.ls.loaded[in.path] = true
	c.ls.selfOnly[in.path] = true
}

// markInRoot loads (with closure) every instance in lock root `root` whose identity
// matches one of the patterns; self loads only the matched packages' own code.
func (c *closer) markInRoot(root string, patterns []string, label string, self bool) bool {
	hit := false
	for _, p := range c.m.sortedPaths() {
		in := c.m.inst[p]
		if in.root != root || !matchesAny(in.name, patterns) {
			continue
		}
		hit = true
		if self {
			c.selfLoad(in)
			continue
		}
		if !c.seen(in) {
			c.label = label
			c.add(in)
		}
	}
	c.drain()
	return hit
}

func matchesAny(name string, patterns []string) bool {
	for _, p := range patterns {
		switch {
		case strings.HasPrefix(p, "*"):
			if strings.HasSuffix(name, p[1:]) {
				return true
			}
		case strings.HasSuffix(p, "*"):
			if strings.HasPrefix(name, p[:len(p)-1]) {
				return true
			}
		case p == name:
			return true
		}
	}
	return false
}

// --- injectors -----------------------------------------------------------------------

// buildInjectors: when a trigger package is installed in a lock root, the listed packages are
// loaded in that root. Babel/TypeScript/SWC inject helper imports into compiled output
// (closure), bundlers inline their own runtime modules, loader runtimes and Node polyfills.
// A bundler's own code is loaded self-only: its build-time dependency closure is not.
var buildInjectors = []struct {
	triggers []string
	closure  []string
	self     []string
}{
	{[]string{"@babel/core", "babel-core", "@babel/preset-env", "babel-preset-react-app", "babel-loader"},
		[]string{"core-js", "core-js-pure", "regenerator-runtime", "@babel/runtime", "@babel/runtime-corejs2",
			"@babel/runtime-corejs3", "babel-runtime", "@babel/polyfill", "babel-polyfill", "react-app-polyfill"}, nil},
	{[]string{"typescript"}, []string{"tslib"}, nil},
	{[]string{"@swc/core", "@swc/cli", "next"}, []string{"@swc/helpers", "regenerator-runtime"}, nil},
	{bundlers,
		append([]string{"node-libs-browser", "@parcel/node-libs-browser", "rollup-plugin-node-polyfills",
			"rollup-plugin-polyfill-node", "node-polyfill-webpack-plugin", "vite-plugin-node-polyfills", "systemjs",
			"core-js", "regenerator-runtime"}, nodePolyfills...),
		append([]string{"style-loader", "css-loader", "vue-loader", "vue-style-loader", "mini-css-extract-plugin",
			"svelte-loader", "@parcel/runtime-*", "@vite/*"}, bundlers...)},
}

var bundlers = []string{
	"webpack", "react-scripts", "vite", "next", "parcel", "parcel-bundler", "rollup", "@vue/cli-service", "nuxt",
	"@angular-devkit/build-angular", "gatsby", "browserify", "@rspack/core", "snowpack", "@remix-run/dev", "astro",
	"@sveltejs/kit", "umi", "metro",
}

var nodePolyfills = []string{
	"process", "buffer", "events", "util", "url", "punycode", "querystring", "querystring-es3", "path-browserify",
	"stream-browserify", "crypto-browserify", "os-browserify", "assert", "string_decoder", "timers-browserify",
	"tty-browserify", "vm-browserify", "constants-browserify", "domain-browser", "https-browserify", "stream-http",
	"browserify-zlib", "console-browserify", "setimmediate", "readable-stream", "inherits",
}

func (c *closer) applyInjectors() {
	for _, root := range c.m.roots {
		for _, inj := range buildInjectors {
			trig := c.firstPresent(root, inj.triggers)
			if trig == "" {
				continue
			}
			label := "injected by " + trig
			a := c.markInRoot(root, inj.closure, label, false)
			b := c.markInRoot(root, inj.self, label, true)
			if a || b {
				c.ls.injectors[trig] = true
			}
		}
	}
}

func (c *closer) firstPresent(root string, names []string) string {
	for _, n := range names {
		for _, in := range c.m.byName[n] {
			if in.root == root {
				return n
			}
		}
	}
	return ""
}

// --- enumerating loaders -------------------------------------------------------------

// enumeratingLoaders lists packages that load other packages by a name absent from their own
// manifest, where first-party code or config picks the name (a view engine, a SQL client, a
// babel or webpack plugin). When a loader is loaded, its targets (exact names or `*` patterns)
// installed in the same lock root are loaded too; an unbounded loader emits a ScopedReason with
// nil Targets, which blocks every refutation. A dependency's own soft import (debug probing for
// supports-color) has no row: only packages outside the runtime install closure refute, and a
// production install never puts those on disk for a soft import to find.
var enumeratingLoaders = []struct {
	loader    string
	targets   []string
	unbounded bool
}{
	{"express", viewEngines, false},
	{"consolidate", viewEngines, false},
	{"@fastify/view", viewEngines, false},
	{"point-of-view", viewEngines, false},
	{"koa-views", viewEngines, false},
	{"pug", []string{"jstransformer-*"}, false},
	{"jstransformer", []string{"jstransformer-*"}, false},
	{"knex", sqlDrivers, false},
	{"sequelize", sqlDrivers, false},
	{"typeorm", append([]string{"mongodb", "redis", "ioredis", "@sap/hana-client", "sql.js", "react-native-sqlite-storage"}, sqlDrivers...), false},
	{"objection", sqlDrivers, false},
	{"config", []string{"js-yaml", "yaml", "json5", "hjson", "toml", "cson", "properties", "x2js", "coffeescript", "iced-coffee-script", "ts-node"}, false},
	{"@nestjs/core", []string{"@nestjs/*", "class-validator", "class-transformer", "reflect-metadata", "rxjs", "kafkajs", "mqtt",
		"nats", "ioredis", "amqplib", "amqp-connection-manager", "@grpc/grpc-js", "@grpc/proto-loader", "cache-manager"}, false},
	{"pino", []string{"pino-*", "thread-stream", "sonic-boom"}, false},
	{"log4js", []string{"@log4js-node/*"}, false},
	{"winston", []string{"winston-*"}, false},
	{"keyv", []string{"@keyv/*"}, false},
	{"@babel/core", []string{"@babel/plugin-*", "@babel/preset-*", "babel-plugin-*", "babel-preset-*", "@babel/runtime*"}, false},
	{"@babel/register", []string{"@babel/plugin-*", "@babel/preset-*", "babel-plugin-*", "babel-preset-*"}, false},
	{"webpack", []string{"*-loader", "*-webpack-plugin", "webpack-*"}, false},
	{"next", []string{"@next/*", "sharp", "critters", "@opentelemetry/api", "@babel/plugin-*", "@babel/preset-*", "babel-plugin-*",
		"styled-jsx", "@swc/helpers", "react", "react-dom"}, false},
	{"eslint", []string{"eslint-plugin-*", "eslint-config-*", "@*/eslint-plugin*", "@*/eslint-config*", "*-eslint-parser", "@typescript-eslint/*"}, false},
	{"jest", []string{"jest-*", "@jest/*", "babel-jest", "ts-jest"}, false},
	{"postcss", []string{"postcss-*", "autoprefixer", "tailwindcss", "cssnano"}, false},
	{"loopback", []string{"loopback-*"}, false},
	{"@loopback/core", []string{"@loopback/*", "loopback-connector-*"}, false},
	{"sails", []string{"sails-*"}, false},
	{"egg", []string{"egg-*", "@eggjs/*"}, false},
	{"@strapi/strapi", []string{"@strapi/*", "strapi-*"}, false},
	{"passport", []string{"passport-*"}, false},
	{"gulp", []string{"gulp-*"}, false},
	{"grunt", []string{"grunt-*"}, false},
	{"karma", []string{"karma-*"}, false},
	{"module-alias", nil, true},
	{"glue", nil, true},
	{"require-all", nil, true},
	{"require-directory", nil, true},
}

var viewEngines = []string{
	"pug", "jade", "ejs", "hbs", "handlebars", "express-handlebars", "mustache", "nunjucks", "twig", "swig", "swig-templates",
	"dot", "marko", "liquid", "liquidjs", "eta", "squirrelly", "vash", "hogan.js", "atpl", "dustjs-linkedin", "haml",
	"hamljs", "teacup", "underscore", "lodash", "whiskers", "react-dom", "express-react-views", "ect", "ractive",
	"velocityjs", "walrus", "toffee", "templayed", "bracket-template", "htmling", "just", "plates", "qejs", "slm",
	"arc-templates", "babel-core", "@babel/core", "coffeecup", "dust", "dustjs-helpers", "haml-coffee", "mote", "nunjucks",
	"razor-tmpl", "tinyliquid", "vue-server-renderer", "vue", "express-art-template", "art-template",
}

var sqlDrivers = []string{
	"pg", "pg-native", "pg-query-stream", "mysql", "mysql2", "sqlite3", "better-sqlite3", "@vscode/sqlite3", "tedious",
	"oracledb", "mariadb", "pg-hstore", "ibm_db", "snowflake-sdk", "@google-cloud/spanner", "sql.js", "mssql",
}

func (c *closer) applyLoaders() {
	fired := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, l := range enumeratingLoaders {
			for _, in := range c.m.byName[l.loader] {
				key := l.loader + "\x00" + in.root
				if !c.ls.loaded[in.path] || c.ls.selfOnly[in.path] || fired[key] {
					continue
				}
				fired[key] = true
				changed = true
				c.ls.loaders[l.loader] = true
				if l.unbounded {
					c.ls.scoped = append(c.ls.scoped, plugin.ScopedReason{
						Reason:  plugin.PartialReasonComputedRequireSpecifier,
						Package: "pkg:npm/" + l.loader,
					})
					continue
				}
				c.markInRoot(in.root, l.targets, "loaded by "+l.loader, false)
			}
		}
	}
}

// --- first-party scan ----------------------------------------------------------------

type fileClass int

const (
	classRuntime fileClass = iota
	classDev
	classInjector // build config: referenced packages are bundled with their whole resolution reach
)

type firstPartyRoots struct {
	runtime []rootRef
	config  []rootRef // build-config references, closed by the build-config closer
	dev     []rootRef
	install []installSeed // production-install edges of every first-party manifest
	names   []string      // `name` of every first-party manifest
}

var (
	codeExts     = map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".mts": true, ".cts": true, ".vue": true, ".svelte": true}
	markupExts   = map[string]bool{".html": true, ".htm": true, ".ejs": true, ".pug": true, ".jade": true, ".hbs": true, ".handlebars": true, ".njk": true, ".css": true, ".scss": true, ".sass": true, ".less": true, ".styl": true}
	devSegments  = map[string]bool{"test": true, "tests": true, "__tests__": true, "__mocks__": true, "__fixtures__": true, "spec": true, "specs": true, "e2e": true, "cypress": true, "stories": true, "__snapshots__": true}
	devTestFile  = regexp.MustCompile(`\.(test|spec|cy|stories|story|e2e)\.[cm]?[jt]sx?$`)
	preloadFlag  = regexp.MustCompile(`(?:^|[\s="'])(?:-r|--require|--import|--loader|--experimental-loader)(?:=|\s+)["']?([^\s"']+)`)
	markupModRef = regexp.MustCompile(`node_modules/((?:@[\w.\-]+/)?[\w.\-]+)`)
	cssBareRef   = regexp.MustCompile(`(?:@import|@use|@forward)\s+(?:url\()?["']~?((?:@[\w.\-]+/)?[\w.\-]+)|url\(\s*["']?~((?:@[\w.\-]+/)?[\w.\-]+)`)
)

// devConfigStems are tooling configs that only dev tooling reads (tests, lint, format, CSS).
var devConfigStems = map[string]bool{
	"jest": true, "karma": true, "playwright": true, "cypress": true, "vitest": true, "commitlint": true, "lint-staged": true,
	"gulpfile": true, "gruntfile": true, "postcss": true, "tailwind": true, "stylelint": true, "prettier": true, "eslint": true,
	".eslintrc": true, ".prettierrc": true, ".mocharc": true, ".lintstagedrc": true, ".stylelintrc": true, ".commitlintrc": true,
	"mocha": true, "nodemon": true, "wdio": true, "protractor": true, "jasmine": true, "ava": true, ".nycrc": true,
	"setuptests": true, "jest.setup": true, "setupproxy": true, "babel-jest": true, ".huskyrc": true, ".storybook": true,
	"storybook": true, "jsdoc": true, "typedoc": true, "renovate": true, ".releaserc": true, "release.config": true,
}

// injectorConfigStems are build configs whose referenced packages can land in runtime output.
var injectorConfigStems = map[string]bool{
	"webpack": true, "vite": true, "rollup": true, "babel": true, ".babelrc": true, "vue": true, "craco": true, "svelte": true,
	"astro": true, "esbuild": true, "snowpack": true, "metro": true, "quasar": true, "config-overrides": true, "razzle": true,
	"tsup": true, "rspack": true, "rsbuild": true, "parcel": true, ".parcelrc": true, "remix": true, "angular": true,
}

func configStem(base string) string {
	b := strings.ToLower(base)
	if strings.HasPrefix(b, ".") {
		if i := strings.IndexByte(b[1:], '.'); i >= 0 {
			return b[:i+1]
		}
		return b
	}
	if strings.HasPrefix(b, "jest.setup") {
		return "jest.setup"
	}
	if strings.HasPrefix(b, "release.config") {
		return "release.config"
	}
	if i := strings.IndexByte(b, '.'); i >= 0 {
		return b[:i]
	}
	return b
}

func classifyFile(rel string) fileClass {
	base := path.Base(rel)
	if devTestFile.MatchString(base) {
		return classDev
	}
	for _, seg := range strings.Split(path.Dir(rel), "/") {
		if devSegments[seg] {
			return classDev
		}
	}
	stem := configStem(base)
	if devConfigStems[stem] {
		return classDev
	}
	if !injectorConfigStems[stem] {
		return classRuntime
	}
	// "vite.config.ts", ".babelrc.js", and every "webpack.*.js" are build configs;
	// a plain "vue.js" is not.
	if strings.HasPrefix(stem, ".") || stem == "webpack" || strings.Contains(strings.ToLower(base), "config") {
		return classInjector
	}
	return classRuntime
}

type fpFile struct {
	rel   string
	class fileClass
	// config is set for a build config. Its references stay build-config roots even when
	// runtime code imports the file, since the bundle carries them either way.
	config bool
	refs   []rootRef
	rels   []string // build-relative targets of relative imports
	// Load-set gaps that count only once the file's final class is known: a dev file that
	// runtime code imports runs at runtime.
	unreadable bool
	computed   string // first computed require/import
	wholeDir   string // a literal serving a whole node_modules directory
}

func scanFirstParty(m *installModel, ls *loadSet) firstPartyRoots {
	var files []*fpFile
	byRel := map[string]*fpFile{}
	var manifests []string
	var opsFiles []string
	_ = filepath.WalkDir(m.buildReal, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable subtree: its files are absent from the scan.
		}
		name := d.Name()
		if d.IsDir() {
			if p != m.buildReal && skipDir(name) {
				return filepath.SkipDir
			}
			return nil
		}
		rel := m.rel(p)
		ext := strings.ToLower(path.Ext(name))
		switch {
		case name == "package.json":
			manifests = append(manifests, rel)
		case strings.HasSuffix(name, ".d.ts"):
		case codeExts[ext] || markupExts[ext]:
			f := &fpFile{rel: rel, class: classifyFile(rel)}
			f.config = f.class == classInjector
			files = append(files, f)
			byRel[rel] = f
		case name == ".babelrc" || name == ".babelrc.json" || name == "babel.config.json" || name == ".parcelrc":
			f := &fpFile{rel: rel, class: classInjector, config: true}
			files = append(files, f)
			byRel[rel] = f
		case name == "Procfile" || strings.HasPrefix(name, "Dockerfile") || ext == ".yml" || ext == ".yaml" ||
			strings.HasPrefix(name, ".env") || strings.HasSuffix(name, ".sh"):
			opsFiles = append(opsFiles, rel)
		}
		return nil
	})

	jsonRuntime := map[string]bool{}
	for _, f := range files {
		scanFile(m, f, jsonRuntime)
	}

	// A dev-classified or build-config file imported by runtime code runs at runtime.
	queue := []*fpFile{}
	for _, f := range files {
		if f.class == classRuntime {
			queue = append(queue, f)
		}
	}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		for _, t := range f.rels {
			if g, ok := byRel[t]; ok && g.class != classRuntime {
				g.class = classRuntime
				queue = append(queue, g)
			}
		}
	}

	var out firstPartyRoots
	for _, f := range files {
		if f.unreadable && f.class != classDev {
			ls.gap("%s unreadable", f.rel)
		}
		if f.computed != "" && f.class == classRuntime {
			ls.gap("%s: computed %s", f.rel, f.computed)
		}
		if f.wholeDir != "" && f.class == classRuntime {
			ls.gap("%s serves a whole node_modules directory (%q)", f.rel, f.wholeDir)
		}
		switch {
		case f.config:
			out.config = append(out.config, f.refs...)
		case f.class == classRuntime:
			out.runtime = append(out.runtime, f.refs...)
		case f.class == classDev:
			out.dev = append(out.dev, f.refs...)
		}
	}
	for _, rel := range sortedSet(jsonRuntime) {
		data, err := os.ReadFile(filepath.Join(m.buildReal, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		out.runtime = append(out.runtime, jsonStringRoots(m, data, path.Dir(rel), rel)...)
	}
	for _, rel := range manifests {
		out.manifestRoots(m, rel)
	}
	for _, rel := range opsFiles {
		data, err := os.ReadFile(filepath.Join(m.buildReal, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		for _, mm := range preloadFlag.FindAllStringSubmatch(string(data), -1) {
			if isBareSpecifier(mm[1]) {
				out.runtime = append(out.runtime, rootRef{spec: mm[1], from: dirOf(rel), label: rel + " (preload)", fallback: true})
			}
		}
	}
	return out
}

func sortedSet(s map[string]bool) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dirOf(rel string) string {
	d := path.Dir(rel)
	if d == "." {
		return ""
	}
	return d
}

// scanFile collects a file's package references and relative-import targets.
func scanFile(m *installModel, f *fpFile, jsonRuntime map[string]bool) {
	data, err := os.ReadFile(filepath.Join(m.buildReal, filepath.FromSlash(f.rel)))
	if err != nil {
		f.unreadable = true
		return
	}
	dir := dirOf(f.rel)
	ext := strings.ToLower(path.Ext(f.rel))
	src := string(data)

	if markupExts[ext] {
		for _, mm := range markupModRef.FindAllStringSubmatch(src, -1) {
			f.refs = append(f.refs, rootRef{spec: mm[1], from: dir, label: f.rel, fallback: true})
		}
		for _, mm := range cssBareRef.FindAllStringSubmatch(src, -1) {
			spec := mm[1]
			if spec == "" {
				spec = mm[2]
			}
			if m.knownDir(spec) {
				f.refs = append(f.refs, rootRef{spec: spec, from: dir, label: f.rel, fallback: true})
			}
		}
		return
	}
	if strings.HasSuffix(f.rel, ".json") || path.Base(f.rel) == ".babelrc" || path.Base(f.rel) == ".parcelrc" {
		f.refs = jsonStringRoots(m, data, dir, f.rel)
		return
	}

	switch ext {
	case ".vue", ".svelte":
		script, _, _ := extractSFCBlocks(src)
		src = script
		runtime := "vue"
		if ext == ".svelte" {
			runtime = "svelte"
		}
		f.refs = append(f.refs, rootRef{spec: runtime, from: dir, label: f.rel, fallback: true})
	}

	sc := scanSource(src)
	for _, spec := range sc.specifiers {
		switch {
		case strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || spec == "." || spec == "..":
			if t, ok := m.resolveRelative(dir, spec); ok {
				f.rels = append(f.rels, t)
				if strings.HasSuffix(t, ".json") {
					jsonRuntime[t] = true
				}
			}
		case isBareSpecifier(spec):
			f.refs = append(f.refs, rootRef{spec: spec, from: dir, label: f.rel, fallback: true})
		}
	}
	for _, lit := range sc.literals {
		for _, mm := range preloadFlag.FindAllStringSubmatch(lit, -1) {
			if isBareSpecifier(mm[1]) {
				f.refs = append(f.refs, rootRef{spec: mm[1], from: dir, label: f.rel, fallback: true})
			}
		}
		if spec, whole, ok := literalPackageRef(m, lit); ok {
			f.refs = append(f.refs, rootRef{spec: spec, from: dir, label: f.rel, fallback: true})
		} else if whole && f.wholeDir == "" {
			f.wholeDir = lit
		}
	}
	if len(sc.computed) > 0 {
		f.computed = sc.computed[0]
	}
	if ext == ".jsx" || ext == ".tsx" || sc.jsx {
		for _, rt := range jsxRuntimes {
			f.refs = append(f.refs, rootRef{spec: rt, from: dir, label: f.rel + " (JSX)"})
		}
	}
	for _, rt := range sc.jsxSources {
		f.refs = append(f.refs, rootRef{spec: rt, from: dir, label: f.rel + " (@jsxImportSource)", fallback: true})
	}
}

var jsxRuntimes = []string{"react", "preact", "@emotion/react", "solid-js", "vue", "inferno", "@builder.io/qwik", "hono", "theme-ui"}

func (m *installModel) knownDir(spec string) bool {
	dir, _ := splitBareSpecifier(spec)
	return len(m.byDir[dir]) > 0
}

// literalPackageRef reports whether a runtime string literal names an installed package:
// exactly, as a `name/` subpath, or through a node_modules path. whole is set for a literal
// pointing at a node_modules directory itself.
func literalPackageRef(m *installModel, lit string) (spec string, whole, ok bool) {
	s := strings.TrimSpace(lit)
	if s == "" || len(s) > 214 {
		return "", false, false
	}
	if i := strings.LastIndex(s, "node_modules"); i >= 0 {
		rest := strings.Trim(s[i+len("node_modules"):], "/\\")
		if rest == "" {
			return "", true, false
		}
		s = strings.ReplaceAll(rest, "\\", "/")
	}
	if strings.ContainsAny(s, " \t\n\"'`<>{}()") {
		return "", false, false
	}
	if !m.knownDir(s) {
		return "", false, false
	}
	return s, false, true
}

func jsonStringRoots(m *installModel, data []byte, dir, label string) []rootRef {
	var v any
	if json.Unmarshal(data, &v) != nil {
		return nil
	}
	var out []rootRef
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			if spec, _, ok := literalPackageRef(m, t); ok {
				out = append(out, rootRef{spec: spec, from: dir, label: label, fallback: true})
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(k)
				walk(t[k])
			}
		}
	}
	walk(v)
	return out
}

// manifestRoots reads a first-party package.json: preload flags in scripts and in-process
// runtime bins are runtime roots, `imports`/`browser` package mappings are runtime roots, and
// every other script bin is a dev-tooling root (labels only).
func (out *firstPartyRoots) manifestRoots(m *installModel, rel string) {
	data, err := os.ReadFile(filepath.Join(m.buildReal, filepath.FromSlash(rel)))
	if err != nil {
		return
	}
	var man struct {
		npmLoadPkg
		Scripts map[string]string `json:"scripts"`
		Imports json.RawMessage   `json:"imports"`
		Browser json.RawMessage   `json:"browser"`
	}
	if json.Unmarshal(data, &man) != nil {
		return
	}
	dir := dirOf(rel)
	out.install = append(out.install, runtimeSeeds(man.npmLoadPkg, dir)...)
	if man.Name != "" {
		out.names = append(out.names, man.Name)
	}
	for _, raw := range []json.RawMessage{man.Imports, man.Browser} {
		if len(raw) > 0 {
			out.runtime = append(out.runtime, jsonStringRoots(m, raw, dir, rel)...)
		}
	}
	for _, key := range sortedKeysOf(man.Scripts) {
		cmd := man.Scripts[key]
		label := "scripts." + key
		if dir != "" {
			label = dir + "/package.json " + label
		}
		for _, mm := range preloadFlag.FindAllStringSubmatch(cmd, -1) {
			if isBareSpecifier(mm[1]) {
				out.runtime = append(out.runtime, rootRef{spec: mm[1], from: dir, label: label + " (preload)", fallback: true})
			}
		}
		for _, tok := range scriptTokens(cmd) {
			if pkg, ok := runtimeBins[tok]; ok {
				out.runtime = append(out.runtime, rootRef{spec: pkg, from: dir, label: label + " (" + tok + ")", fallback: true})
				continue
			}
			for _, in := range m.byBin[tok] {
				out.dev = append(out.dev, rootRef{spec: in.dirName, from: dir, label: tok + " (" + label + ")", fallback: true})
				break
			}
		}
	}
}

// runtimeBins are bins that load application code into their own process, so the bin's
// package runs alongside the app (unlike nodemon/concurrently, which spawn a child node).
var runtimeBins = map[string]string{
	"next": "next", "nuxt": "nuxt", "nuxi": "nuxi", "serve": "serve", "http-server": "http-server", "ts-node": "ts-node",
	"ts-node-esm": "ts-node", "tsx": "tsx", "babel-node": "@babel/node", "pm2": "pm2", "pm2-runtime": "pm2",
	"remix-serve": "@remix-run/serve", "react-router-serve": "@react-router/serve", "astro": "astro", "gatsby": "gatsby",
	"fastify": "fastify-cli", "functions-framework": "@google-cloud/functions-framework", "probot": "probot",
	"sails": "sails", "strapi": "@strapi/strapi", "nest": "@nestjs/cli", "egg-scripts": "egg-scripts", "micro": "micro",
	"forever": "forever", "esno": "esno", "vite-node": "vite-node", "svelte-kit": "@sveltejs/kit",
}

func scriptTokens(cmd string) []string {
	f := strings.FieldsFunc(cmd, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '&' || r == '|' || r == ';' || r == '(' || r == ')' || r == '"' || r == '\''
	})
	return f
}

// --- source scanning -----------------------------------------------------------------

type sourceScan struct {
	specifiers []string
	literals   []string
	computed   []string
	jsx        bool
	jsxSources []string
}

var (
	jsxPragma = regexp.MustCompile(`@jsxImportSource\s+(\S+)`)
	jsxTag    = regexp.MustCompile(`(?:return|\(|=>|[=,?:])\s*<([A-Za-z][\w.]*)?[\s/>]`)
)

// scanSource extracts module specifiers, string literals and computed loads from JS/TS
// source, over the comment/string-blanked view so code inside strings never reads as code.
func scanSource(source string) sourceScan {
	var sc sourceScan
	clean := []rune(stripJS(source))
	src := []rune(source)
	n := len(clean)
	if len(src) != n {
		return sc
	}
	for _, mm := range jsxPragma.FindAllStringSubmatch(source, -1) {
		sc.jsxSources = append(sc.jsxSources, strings.Trim(mm[1], "*/ "))
	}
	if jsxTag.MatchString(string(clean)) && (strings.Contains(string(clean), "/>") || strings.Contains(string(clean), "</")) {
		sc.jsx = true
	}
	for p := 0; p < n; p++ {
		c := clean[p]
		if c == '_' && isQuote(src[p]) {
			lit := specifierAt(src, p)
			if src[p] == '`' && strings.Contains(lit, "${") {
				continue
			}
			sc.literals = append(sc.literals, lit)
			if w := prevWord(clean, p); w == "from" || w == "import" {
				sc.specifiers = append(sc.specifiers, lit)
			}
			continue
		}
		if !isIdentStart(c) || (p > 0 && isIdentPart(clean[p-1]) && !isQuote(src[p-1])) {
			continue
		}
		end := p
		for end < n && isIdentPart(clean[end]) && !isQuote(src[end]) {
			end++
		}
		word := string(clean[p:end])
		before := prevNonSpaceAt(clean, p)
		dotted := before >= 0 && clean[before] == '.'
		switch word {
		case "require":
			if dotted && prevWord(clean, before) != "module" || prevWord(clean, p) == "function" {
				break
			}
			q := skipSpace(clean, end)
			if q < n && clean[q] == '.' {
				w, e := readWord(clean, skipSpace(clean, q+1))
				if w != "resolve" {
					break
				}
				q = skipSpace(clean, e)
			}
			if q < n && clean[q] == '(' {
				sc.call(clean, src, q, "require()")
			}
		case "import":
			if q := skipSpace(clean, end); !dotted && q < n && clean[q] == '(' {
				sc.call(clean, src, q, "import()")
			}
		case "createRequire":
			// `const require = createRequire(...)` keeps every load visible as require();
			// a require function under any other name hides its specifiers.
			q := skipSpace(clean, end)
			if dotted || q >= n || clean[q] != '(' {
				break
			}
			if before >= 0 && clean[before] == '=' && prevWord(clean, before) == "require" {
				break
			}
			sc.computed = append(sc.computed, "createRequire()")
		}
		p = end - 1
	}
	return sc
}

// call records the argument of a require(/import( at clean[open] == '('.
func (sc *sourceScan) call(clean, src []rune, open int, what string) {
	a := skipSpace(clean, open+1)
	if a < len(clean) && clean[a] == '_' && isQuote(src[a]) {
		lit := specifierAt(src, a)
		close := skipSpace(clean, skipStringEnd(src, a))
		literal := !(src[a] == '`' && strings.Contains(lit, "${"))
		if literal && close < len(clean) && (clean[close] == ')' || clean[close] == ',') {
			sc.specifiers = append(sc.specifiers, lit)
			return
		}
	}
	sc.computed = append(sc.computed, what)
}

// skipStringEnd returns the index just past the string literal starting at src[pos].
func skipStringEnd(src []rune, pos int) int {
	quote := src[pos]
	for i := pos + 1; i < len(src); i++ {
		if src[i] == '\\' {
			i++
			continue
		}
		if src[i] == quote {
			return i + 1
		}
	}
	return len(src)
}

func isQuote(r rune) bool { return r == '\'' || r == '"' || r == '`' }

// prevNonSpaceAt returns the index of the last non-space rune before p, or -1.
func prevNonSpaceAt(clean []rune, p int) int {
	for i := p - 1; i >= 0; i-- {
		if clean[i] != ' ' && clean[i] != '\t' && clean[i] != '\n' && clean[i] != '\r' {
			return i
		}
	}
	return -1
}

// prevWord returns the identifier ending immediately (whitespace aside) before clean[p].
func prevWord(clean []rune, p int) string {
	i := p - 1
	for i >= 0 && (clean[i] == ' ' || clean[i] == '\t' || clean[i] == '\n' || clean[i] == '\r') {
		i--
	}
	end := i + 1
	for i >= 0 && isIdentPart(clean[i]) {
		i--
	}
	if i >= 0 && clean[i] == '.' {
		return ""
	}
	return string(clean[i+1 : end])
}

// resolveRelative resolves a relative specifier to a first-party file, build-relative.
func (m *installModel) resolveRelative(dir, spec string) (string, bool) {
	base := joinRel(dir, spec)
	if !m.inside(base) {
		return "", false
	}
	cands := []string{base}
	for _, e := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".vue", ".svelte"} {
		cands = append(cands, base+e)
	}
	for _, e := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json"} {
		cands = append(cands, base+"/index"+e)
	}
	for _, c := range cands {
		if fi, err := os.Stat(filepath.Join(m.buildReal, filepath.FromSlash(c))); err == nil && !fi.IsDir() {
			return c, true
		}
	}
	return "", false
}

func isBareSpecifier(spec string) bool {
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "#") ||
		strings.HasPrefix(spec, "~/") || strings.HasPrefix(spec, "@/") || strings.Contains(spec, ":") || strings.ContainsAny(spec, " \t\n") {
		return false
	}
	dir, _ := splitBareSpecifier(spec)
	return !isNodeBuiltin(dir)
}

func isNodeBuiltin(name string) bool {
	return nodeBuiltins[strings.TrimPrefix(name, "node:")]
}

var nodeBuiltins = func() map[string]bool {
	out := map[string]bool{}
	for _, n := range strings.Fields(`assert async_hooks buffer child_process cluster console constants crypto dgram
		diagnostics_channel dns domain events fs http http2 https inspector module net os path perf_hooks process
		punycode querystring readline repl stream string_decoder sys timers tls trace_events tty url util v8 vm wasi
		worker_threads zlib test sqlite sea`) {
		out[n] = true
	}
	return out
}()

// --- refutation ----------------------------------------------------------------------

// npmPackageRef parses "pkg:npm/<name>@<version>" (namespace percent-encoded or not) into
// name and version. ok is false for any other ecosystem or a missing version.
func npmPackageRef(purl string) (name, version string, ok bool) {
	rest, found := strings.CutPrefix(purl, "pkg:npm/")
	if !found {
		return "", "", false
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	slash := strings.LastIndexByte(rest, '/')
	at := strings.LastIndexByte(rest, '@')
	if at <= slash || at == len(rest)-1 {
		return "", "", false
	}
	n, err1 := url.PathUnescape(rest[:at])
	v, err2 := url.PathUnescape(rest[at+1:])
	if err1 != nil || err2 != nil || n == "" {
		return "", "", false
	}
	return canonicalNpmName(n), v, true
}

// canonicalNpmName is npm's case of the arm B name rule (the ReachabilityRequest.Package
// contract in plugin/plugin.go; the gate's side is trigger's normalizePackageName): npm names
// compare exactly, `name` or `@scope/name`, after a PURL's percent-encoding is decoded. Both
// sides of every comparison go through it: the requested Package and each installed name.
func canonicalNpmName(name string) string { return name }

// npmPackageKey returns the canonical npm name a package URL names, ignoring version,
// qualifiers and subpath and decoding percent-encoding: the key trigger's purlKey compares on.
// ok is false for anything that is not an npm package URL.
func npmPackageKey(purl string) (string, bool) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", false
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	typ, p, ok := strings.Cut(rest, "/")
	if !ok || !strings.EqualFold(typ, "npm") || p == "" {
		return "", false
	}
	if at := strings.LastIndex(p, "@"); at > strings.LastIndex(p, "/") {
		p = p[:at]
	}
	dec, err := url.PathUnescape(p)
	if err != nil || dec == "" {
		return "", false
	}
	return canonicalNpmName(dec), true
}

// scopedReaches reports whether scoped reason s could hide a load of the npm package with
// canonical name `name`: it names no targets, or its Package or one of its Targets names the
// package. A Package or Target that does not parse as an npm package URL counts as naming it.
func scopedReaches(s plugin.ScopedReason, name string) bool {
	if len(s.Targets) == 0 {
		return true
	}
	refs := s.Targets
	if s.Package != "" {
		refs = append([]string{s.Package}, s.Targets...)
	}
	for _, r := range refs {
		if k, ok := npmPackageKey(r); !ok || k == name {
			return true
		}
	}
	return false
}

// refute returns the package_not_loaded refutation for name@version, or nil when any
// condition fails. The gate matches a refutation on type and name only, never version, so the
// condition covers every installed copy of the canonical name, at any version: no copy is
// loaded, every copy sits outside the runtime install closure, and at least one copy is at the
// admitted version. It also fails when the load set is incomplete, a counted scoped reason can
// reach the package, the name is one of the project's own packages, or an install link leaves
// the build dir (copies there cannot be enumerated).
func (ls *loadSet) refute(name, version string) *plugin.Refutation {
	if !ls.complete || ls.model == nil {
		return nil
	}
	name = canonicalNpmName(name)
	if ls.ownNames[name] {
		return nil
	}
	purl := "pkg:npm/" + name
	for _, s := range ls.scoped {
		if scopedReaches(s, name) {
			return nil
		}
	}
	for _, ip := range sortedKeysOf(ls.model.links) {
		t := ls.model.links[ip]
		if t == linkExternal {
			return nil
		}
		if isInstallPath(t) && ls.model.indexDiskPackage(t) == nil {
			return nil
		}
	}
	instances := append([]*pkgInstance(nil), ls.model.byName[name]...)
	sort.Slice(instances, func(i, j int) bool { return instances[i].path < instances[j].path })
	atVersion := 0
	for _, in := range instances {
		if ls.loaded[in.path] || !ls.devOnly(in) {
			return nil
		}
		if in.version == version {
			atVersion++
		}
	}
	if atVersion == 0 {
		return nil
	}
	return &plugin.Refutation{
		Basis:   plugin.RefutationPackageNotLoaded,
		Package: purl,
		Detail:  ls.detail(name, instances, atVersion),
	}
}

func (ls *loadSet) detail(name string, instances []*pkgInstance, atVersion int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d installed copies of %s (%d at this version), none in the runtime load set", len(instances), name, atVersion)
	rootNames := sortedKeysOfAny(ls.roots)
	fmt.Fprintf(&b, " (%d of %d instances loaded from %d first-party roots", len(ls.loaded), len(ls.model.inst), len(rootNames))
	if len(rootNames) > 0 {
		shown := rootNames
		if len(shown) > 8 {
			shown = shown[:8]
		}
		b.WriteString(": " + strings.Join(shown, ", "))
		if len(rootNames) > len(shown) {
			fmt.Fprintf(&b, ", +%d more", len(rootNames)-len(shown))
		}
	}
	b.WriteString(")")
	if len(ls.loaders) > 0 {
		b.WriteString("; loaders expanded: " + strings.Join(sortedSet(ls.loaders), ", "))
	}
	if len(ls.injectors) > 0 {
		b.WriteString("; injectors: " + strings.Join(sortedSet(ls.injectors), ", "))
	}
	for _, in := range instances {
		if label, ok := ls.devFrom[in.path]; ok {
			b.WriteString("; only reachable from dev tooling: " + label)
			return b.String() + devOnlyNote
		}
	}
	b.WriteString("; not reachable from any first-party root or package script")
	return b.String() + devOnlyNote
}

// devOnlyNote closes every refutation detail: the class (i) evidence and its assumption.
const devOnlyNote = "; outside the runtime install closure (lockfile dev marker, unreachable from every manifest's " +
	"dependencies/optionalDependencies/peerDependencies); assumes dev/tooling groups are not installed at runtime"

func sortedKeysOfAny(mp map[string]string) []string {
	out := make([]string, 0, len(mp))
	for k := range mp {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
