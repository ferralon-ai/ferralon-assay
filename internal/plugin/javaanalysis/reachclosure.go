package javaanalysis

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reachclosure.go — the whole-program classpath a bytecode reachability search runs over:
// the build's compiled classes plus every dependency JAR on the runtime classpath the build
// graph resolved (RuntimeSelection). Each JAR is the file the graph names, read only when it
// still has the digest the graph recorded; nothing is fetched or looked up in a cache.
//
// Every blind spot is a ScopedReason bounded by what the unseen code could call, callbacks
// into first-party code included (BlindSpotTargets):
//   - a runtime node whose file is not a JAR → tool_failure:no_dependency_artifact;
//   - a package the runtime classpath holds at more than one version →
//     relationship_unexpressed:dependency_version_ambiguous (searching one pick would be a
//     guess at which body runs);
//   - a JAR that cannot be read, no longer has its recorded digest, cannot be opened, or holds
//     classes that fail to parse → tool_failure;
//   - a class two JARs define → relationship_unexpressed:duplicate_class (the engine keeps
//     one body per binary name, so the other body's calls are unseen);
//   - a multi-release override (META-INF/versions/N/) that cannot be merged into its base
//     class (classfile.ReleaseMerge) → tool_failure:multi_release_unmerged, also declared
//     run-wide in Reasons so no empty search is Searched. A mergeable override is read: its
//     calls count as the class's own, since a JDK at release N runs it.
//
// A call into a class that is neither loaded nor a JDK platform class is an
// unloaded_dependency hazard inside depreach, so code the graph never listed is never
// silently trusted.
//
// This mirrors kotlinanalysis's dependency closure rather than sharing a package with it:
// the two lanes read first-party code differently (Java from source plus compiled output,
// Kotlin from bytecode only), and the shared part is the loop below.

const (
	reasonDuplicateClass             = plugin.PartialReasonRelationshipUnexpressed + ":duplicate_class"
	reasonDependencyVersionAmbiguous = plugin.PartialReasonRelationshipUnexpressed + ":dependency_version_ambiguous"
	reasonMultiReleaseUnmerged       = plugin.PartialReasonToolFailure + ":multi_release_unmerged"
)

// reachClosure is the engine over first-party plus dependency bytecode and the scoped blind
// spots loading the dependencies incurred.
type reachClosure struct {
	Engine *depreach.Engine
	// mu serialises searches over Engine, whose link mode and per-root search memo every search
	// sets. A cache hit copies the closure and shares Engine, and Reachability is a library
	// entry point a caller may run concurrently, so the copies share mu as well.
	mu *sync.Mutex
	// key fingerprints the inputs the engine was built from (loadReachClosure).
	key    string
	Scoped []plugin.ScopedReason
	// methods indexes every loaded method by depreach's MethodRef.String() key, for the
	// sink-concreteness check.
	methods map[string]classfile.Method
	// classes indexes every loaded class by binary name, for the launch-entry ancestor walk.
	classes map[string]*classfile.Class
	// Loaded maps "group:artifact:version" to the JAR that was opened, for evidence.
	Loaded map[string]string
	// Reasons are declared run-wide and mean the loaded bytes may not be the code that runs, so
	// no empty search is Searched: no build graph (PartialReasonBuildGraphAbsent), a build of the
	// other tool beside the graph's (PartialReasonOtherToolBuild), or a launch option the lanes do
	// not model (LaunchOptionReasons). The Kotlin closure declares the same
	// set. An unmerged multi-release override (reasonMultiReleaseUnmerged) is added
	// here as well.
	Reasons []string
	// releaseReasons are the run-wide reasons loading the JARs incurred, kept with the cached
	// engine.
	releaseReasons []string
	// Listed is set when the loaded classes are every class the build's runtime classpath
	// defines: the graph lists the runtime classpath (RuntimeListed), every entry was listed,
	// every class each JAR holds was read, no two JARs define one class (the copy kept is not
	// the one first on the classpath), and the runtime is a recorded JDK after 8, whose
	// extension directories add to the classpath. The launch is the caller's to check.
	Listed bool
	// unread is set when a JAR could not be opened or holds a class that failed to parse.
	unread bool
	// shadowed is set when two JARs define the same class.
	shadowed bool
	// jdk is the feature release the classes were indexed for.
	jdk int
	// referenced holds every class a loaded class's constant pool names, simpleNames the
	// simple name of every loaded class, kotlinPkgs the package of every loaded class carrying
	// Kotlin metadata and kotlinRefPkgs the package of every class those name: what absent reads
	// for another route a sink's code can take.
	referenced    map[string]bool
	simpleNames   map[string]bool
	kotlinPkgs    map[string]bool
	kotlinRefPkgs map[string]bool
}

// gav is one loaded dependency JAR: a coordinate at a version, and its classifier when the
// build loads a variant file.
type gav struct{ coordinate, version, classifier string }

func (g gav) String() string {
	s := g.coordinate + ":" + g.version
	if g.classifier != "" {
		s += ":" + g.classifier
	}
	return s
}

// closureCache keeps the last engine built per build dir, and per reactor unit within it. The
// pipeline asks Reachability once per advisory, and every ask would otherwise rebuild the
// hierarchy over the whole closure. The key fingerprints every input (JAR paths and digests; the first-party classes in
// full; the classpath), so any change rebuilds. It holds at most closureCacheCap entries, and
// drops the least recently used first.
var closureCache = struct {
	sync.Mutex
	m    map[string]closureEntry
	tick uint64
}{m: map[string]closureEntry{}}

type closureEntry struct {
	key  string
	rc   *reachClosure
	used uint64 // closureCache.tick when last stored or looked up
}

// closureCacheCap bounds the engines closureCache holds: a long-lived process searching many
// builds, or a reactor of many units, keeps at most this many.
const closureCacheCap = 16

// cacheClosure stores e under key, first dropping the least recently used other entry when the
// cache is full.
func cacheClosure(key string, e closureEntry) {
	closureCache.Lock()
	defer closureCache.Unlock()
	if _, ok := closureCache.m[key]; !ok && len(closureCache.m) >= closureCacheCap {
		var lru string
		for k, v := range closureCache.m {
			if lru == "" || v.used < closureCache.m[lru].used {
				lru = k
			}
		}
		delete(closureCache.m, lru)
	}
	closureCache.tick++
	e.used = closureCache.tick
	closureCache.m[key] = e
}

// cachedClosure returns the entry under key, marking it used.
func cachedClosure(key string) (closureEntry, bool) {
	closureCache.Lock()
	defer closureCache.Unlock()
	e, ok := closureCache.m[key]
	if ok {
		closureCache.tick++
		e.used = closureCache.tick
		closureCache.m[key] = e
	}
	return e, ok
}

// loadReachClosure loads every runtime JAR the build graph names. firstParty is the build's
// compiled output and fpClasspath what its directories define: it goes into the engine, and a
// dependency class with the same binary name is skipped, since the build output is what the
// build packaged. Without a graph only firstParty is loaded, and the closure says so run-wide.
// The engine runs on the JDK the graph's run conditions state. A per-unit search (withUnit) loads
// the unit module's runtime classpath only; the launch options, the JDK and the graph's
// completeness stay the whole graph's.
func loadReachClosure(buildDir string, firstParty []classfile.Class, fpClasspath depreach.Classpath, opts ...Option) (*reachClosure, error) {
	g := BuildGraph(opts...)
	reasons := LaunchOptionReasons(buildDir, g)
	unit := resolveOptions(opts).unit
	var mods []buildgraph.Module
	if g != nil {
		mods = g.Modules
		if unit != "" {
			mods = unitModules(g, unit)
		}
	}
	cacheKey := buildDir
	if unit != "" {
		cacheKey += "\x00" + unit
	}

	targetsMemo := map[string][]string{}
	targets := func(coord string) []string {
		if t, ok := targetsMemo[coord]; ok {
			return t
		}
		var t []string
		if g != nil {
			t = blindSpotTargets(mods, coord)
		}
		targetsMemo[coord] = t
		return t
	}
	scoped := func(reason, coord, path string) plugin.ScopedReason {
		return plugin.ScopedReason{Reason: reason, Package: mavenPURLNoVersion(coord), Path: path, Targets: targets(coord)}
	}

	rc := &reachClosure{Loaded: map[string]string{}}
	type opened struct {
		gav gav
		jar artifactJar
	}
	var jars []opened
	var cp depreach.Classpath
	cp.Merge(fpClasspath)
	fp := sha256.New()
	whole := g != nil && (unit == "" || len(mods) > 0) && runtimeListed(g, mods, buildDir) && g.RuntimeJDK() > 8
	if g == nil {
		cp.Unlisted = true
		reasons = append([]string{PartialReasonBuildGraphAbsent}, reasons...)
	} else {
		cp.JDK = g.RuntimeJDK()
		if OtherToolBuild(g, buildDir) {
			reasons = append([]string{PartialReasonOtherToolBuild}, reasons...)
		}
		load, miss := runtimeSelection(g, mods)
		for _, m := range miss {
			cp.Unlisted = true // no JAR is listed for it
			reason := reasonNoDependencyArtifact
			if m.Ambiguous {
				reason = reasonDependencyVersionAmbiguous
			}
			rc.Scoped = append(rc.Scoped, scoped(reason, m.Coordinate, m.Detail))
		}
		for _, j := range load {
			n := gav{coordinate: j.Coordinate, version: j.Version, classifier: j.Classifier}
			jar, found := readJar(j)
			if found != jarFound {
				cp.Unlisted = true
				rc.Scoped = append(rc.Scoped, scoped(plugin.PartialReasonToolFailure, n.coordinate, n.String()+": "+filepath.Base(j.Path)+" unreadable or changed since the build resolved it"))
				continue
			}
			pkgs, listed, closed := classfile.JarBytesPackages(jar.data)
			cp.Add(pkgs, listed && closed)
			fmt.Fprintln(fp, j.Path, j.SHA256)
			jars = append(jars, opened{n, jar})
		}
	}
	fmt.Fprintln(fp, firstPartyFingerprint(firstParty))
	fmt.Fprintln(fp, classpathFingerprint(cp))
	fingerprint := hex.EncodeToString(fp.Sum(nil))

	hit, ok := cachedClosure(cacheKey)
	if ok && hit.key == fingerprint {
		out := *hit.rc
		out.Scoped = append(rc.Scoped, hit.rc.Scoped...)
		out.Reasons = append(reasons, hit.rc.releaseReasons...)
		out.Listed = whole && !cp.Unlisted && !hit.rc.unread && !hit.rc.shadowed
		return &out, nil
	}

	isFirstParty := make(map[string]bool, len(firstParty))
	for _, c := range firstParty {
		isFirstParty[c.Name] = true
	}
	built := &reachClosure{Loaded: map[string]string{}, mu: &sync.Mutex{}}
	definedBy := map[string]gav{}
	shadowReported := map[string]bool{}
	all := append([]classfile.Class{}, firstParty...)
	versioned := make([][]classfile.VersionedClass, len(jars))
	for ji, j := range jars {
		jr, err := loadJarCached(j.jar)
		if err != nil {
			built.unread = true
			built.Scoped = append(built.Scoped, scoped(plugin.PartialReasonToolFailure, j.gav.coordinate, j.gav.String()+": "+err.Error()))
			continue
		}
		if len(jr.Failed) > 0 {
			built.unread = true
			built.Scoped = append(built.Scoped, scoped(plugin.PartialReasonToolFailure, j.gav.coordinate, j.gav.String()+"!"+strings.SplitN(jr.Failed[0], ": ", 2)[0]))
		}
		built.Loaded[j.gav.String()] = j.jar.path
		versioned[ji] = jr.Versioned
		for _, c := range jr.Classes {
			if isFirstParty[c.Name] {
				continue
			}
			if prev, dup := definedBy[c.Name]; dup {
				if key := prev.String() + "|" + j.gav.String(); !shadowReported[key] {
					shadowReported[key] = true
					built.Scoped = append(built.Scoped, scoped(reasonDuplicateClass, j.gav.coordinate, fmt.Sprintf("%s shadowed by %s: %s", j.gav, prev, c.Name)))
				}
				built.shadowed = true
				continue
			}
			definedBy[c.Name] = j.gav
			all = append(all, c)
		}
	}
	gavs := make([]gav, len(jars))
	for i, j := range jars {
		gavs[i] = j.gav
	}
	all = mergeReleases(built, all, gavs, versioned, definedBy, isFirstParty, scoped)
	built.Engine = depreach.NewEngineOn(all, cp)
	built.key = fingerprint
	built.index(all, cp.JDK)

	cacheClosure(cacheKey, closureEntry{key: fingerprint, rc: built})

	out := *built
	out.Scoped = append(rc.Scoped, built.Scoped...)
	out.Reasons = append(reasons, built.releaseReasons...)
	out.Listed = whole && !cp.Unlisted && !built.unread && !built.shadowed
	return &out, nil
}

// mergeReleases folds each JAR's multi-release overrides into the classes it defines and
// returns the class set with any class only an override defines appended. An override of a
// class the build output or another JAR defines is not loaded with that name on any
// release, except where it is the first definition, which is a duplicate the same as two
// base entries. An override that cannot be merged is a scoped tool_failure plus a run-wide
// reason.
func mergeReleases(built *reachClosure, all []classfile.Class, gavs []gav, versioned [][]classfile.VersionedClass, definedBy map[string]gav, isFirstParty map[string]bool, scoped func(reason, coord, path string) plugin.ScopedReason) []classfile.Class {
	n := 0
	for _, vs := range versioned {
		n += len(vs)
	}
	if n == 0 {
		return all
	}
	// Classes only an override defines live in extra, sized up front so the pointers the
	// merge holds into it stay valid.
	extra := make([]classfile.Class, 0, n)
	merge := classfile.NewReleaseMerge(all)
	merge.JDKType = func(name string) bool { return depreach.BootOnly(name, 0) }
	unmerged := func(g gav, detail string) {
		built.Scoped = append(built.Scoped, scoped(reasonMultiReleaseUnmerged, g.coordinate, g.String()+"!"+detail))
		if !slices.Contains(built.releaseReasons, reasonMultiReleaseUnmerged) {
			built.releaseReasons = append(built.releaseReasons, reasonMultiReleaseUnmerged)
		}
	}
	shadowReported := map[string]bool{}
	for ji, vs := range versioned {
		g := gavs[ji]
		vs = slices.Clone(vs)
		sort.SliceStable(vs, func(a, b int) bool { return vs[a].Release < vs[b].Release })
		for _, v := range vs {
			name := v.Class.Name
			if isFirstParty[name] {
				continue
			}
			owner, defined := definedBy[name]
			switch {
			case !defined:
				definedBy[name] = g
				extra = append(extra, v.Class)
				merge.Add(&extra[len(extra)-1])
				continue
			case owner != g:
				if key := owner.String() + "|" + g.String(); !shadowReported[key] {
					shadowReported[key] = true
					built.Scoped = append(built.Scoped, scoped(reasonDuplicateClass, g.coordinate, fmt.Sprintf("%s shadowed by %s: %s", g, owner, v.Entry)))
				}
				built.shadowed = true
				continue
			}
			if err := merge.Merge(v); err != nil {
				unmerged(g, err.Error())
			}
		}
	}
	for _, c := range merge.Check() {
		unmerged(definedBy[c.Class], c.Detail)
	}
	return append(all, extra...)
}

// firstPartyFingerprint digests the first-party classes in full, in a form every process
// derives alike, so it keys both the engine cached in this process and the run cache's entries
// across processes. A class that cannot be encoded gets a digest nothing else matches.
func firstPartyFingerprint(classes []classfile.Class) string {
	lines := make([]string, 0, len(classes))
	for _, c := range classes {
		b, err := exactEncoding(c)
		if err != nil {
			nonce := make([]byte, 16)
			_, _ = rand.Read(nonce)
			return "unkeyed:" + hex.EncodeToString(nonce)
		}
		lines = append(lines, string(b))
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		fmt.Fprintf(h, "%d:%s", len(l), l)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// concrete reports whether the closure holds a body for ref: declared in loaded code and
// neither abstract nor native. Only such a sink can be cleared by an empty search; an
// abstract or native one stands for code the search did not walk.
func (rc *reachClosure) concrete(ref classfile.MethodRef) bool {
	m, ok := rc.methods[ref.String()]
	return ok && !m.Abstract && !m.Native
}

// absent reports whether ref's owner is provably not on the classpath, nor its code by another
// route: the loaded classes are every class it defines (Listed), none is the owner, and the owner
// is no JDK class; no loaded class names the owner, which code compiled against it does and
// which a JAR outside the listed tree (a sibling's shaded artifact, a provided or optional
// dependency) then supplies; no loaded class shares its simple name, as a relocated copy does;
// and no Kotlin compile may have copied the sink's body into a caller without naming its class,
// as an inline function's call does. That copy is in code compiled against the sink's owner:
// first-party code, when any of it is Kotlin (firstPartyKotlin), or a Kotlin dependency that
// shares or names the owner's package. A Kotlin library compiled against other code
// (kotlin-stdlib, okio) is no such caller.
func (rc *reachClosure) absent(ref classfile.MethodRef, firstPartyKotlin bool) bool {
	_, loaded := rc.classes[ref.Owner]
	pkg := classPackage(ref.Owner)
	return rc.Listed && !loaded && !depreach.IsPlatformClass(ref.Owner) && !depreach.BootOnly(ref.Owner, rc.jdk) &&
		!rc.referenced[ref.Owner] && !rc.simpleNames[simpleClassName(ref.Owner)] &&
		!firstPartyKotlin && !rc.kotlinPkgs[pkg] && !rc.kotlinRefPkgs[pkg]
}

// classPackage is name's package, slash-separated, "" for the default package.
func classPackage(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[:i]
	}
	return ""
}

// simpleClassName is name without its package.
func simpleClassName(name string) string {
	return name[strings.LastIndex(name, "/")+1:]
}

// index records the classes and methods of all that run on feature release jdk, as the engine
// does: a classpath copy of a class the JVM may load from the JDK instead is left out.
func (rc *reachClosure) index(all []classfile.Class, jdk int) {
	rc.jdk = jdk
	rc.methods = make(map[string]classfile.Method)
	rc.classes = make(map[string]*classfile.Class, len(all))
	rc.referenced = map[string]bool{}
	rc.simpleNames = make(map[string]bool, len(all))
	rc.kotlinPkgs = map[string]bool{}
	rc.kotlinRefPkgs = map[string]bool{}
	for i := range all {
		kotlin := all[i].KotlinMetadata != nil
		for _, n := range all[i].Refs {
			rc.referenced[n] = true
			if kotlin {
				rc.kotlinRefPkgs[classPackage(n)] = true
			}
		}
		rc.simpleNames[simpleClassName(all[i].Name)] = true
		if kotlin {
			rc.kotlinPkgs[classPackage(all[i].Name)] = true
		}
		if depreach.BootOnly(all[i].Name, jdk) {
			continue
		}
		rc.classes[all[i].Name] = &all[i]
		for _, m := range all[i].Methods {
			rc.methods[m.Ref.String()] = m
		}
	}
}

// class returns the loaded class named name.
func (rc *reachClosure) class(name string) (*classfile.Class, bool) {
	c, ok := rc.classes[name]
	return c, ok
}

// jarCache keeps each parsed JAR for the life of the plugin process, keyed by the digest of
// the bytes readJar checked, so a rewritten JAR is re-read and what is parsed is what was
// checked.
var jarCache = struct {
	sync.Mutex
	m map[string]classfile.JarResult
}{m: map[string]classfile.JarResult{}}

func jarKey(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func loadJarCached(jar artifactJar) (classfile.JarResult, error) {
	key := jarKey(jar.data)
	jarCache.Lock()
	jr, ok := jarCache.m[key]
	jarCache.Unlock()
	if ok {
		return jr, nil
	}
	jr, err := classfile.LoadJarBytesReleases(jar.data)
	if err != nil {
		return classfile.JarResult{}, err
	}
	jarCache.Lock()
	jarCache.m[key] = jr
	jarCache.Unlock()
	return jr, nil
}

// parseDepEdgeSymbol is the inverse of depEdgeSymbol. ok is false for any other symbol form.
func parseDepEdgeSymbol(s string) (classfile.MethodRef, bool) {
	rest, ok := strings.CutPrefix(s, "jvmref ")
	if !ok {
		return classfile.MethodRef{}, false
	}
	owner, nameDesc, ok := strings.Cut(rest, "#")
	if !ok || owner == "" {
		return classfile.MethodRef{}, false
	}
	paren := strings.IndexByte(nameDesc, '(')
	if paren <= 0 {
		return classfile.MethodRef{}, false
	}
	return classfile.MethodRef{Owner: owner, Name: nameDesc[:paren], Descriptor: nameDesc[paren:]}, true
}

// classpathFingerprint renders what cp records, for the closure cache key: the engine's roots
// depend on it beyond the loaded classes.
func classpathFingerprint(cp depreach.Classpath) string {
	pkgs := make([]string, 0, len(cp.Packages))
	for p := range cp.Packages {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	return fmt.Sprintf("jdk=%d unlisted=%t packages=%s", cp.JDK, cp.Unlisted, strings.Join(pkgs, ","))
}
