package javaanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

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

// closureCache keeps the last engine built per build dir. The pipeline asks Reachability
// once per advisory, and every ask would otherwise rebuild the hierarchy over the whole
// closure. The key fingerprints every input (JAR paths, sizes and times; the first-party
// classes' hierarchy, methods and call edges), so any change rebuilds.
var closureCache = struct {
	sync.Mutex
	m map[string]closureEntry
}{m: map[string]closureEntry{}}

type closureEntry struct {
	key string
	rc  *reachClosure
}

// loadReachClosure loads every runtime JAR the build graph names. firstParty is the build's
// compiled output and fpClasspath what its directories define: it goes into the engine, and a
// dependency class with the same binary name is skipped, since the build output is what the
// build packaged. Without a graph only firstParty is loaded, and the closure says so run-wide.
// The engine runs on the JDK the graph's run conditions state.
func loadReachClosure(buildDir string, firstParty []classfile.Class, fpClasspath depreach.Classpath, opts ...Option) (*reachClosure, error) {
	g := BuildGraph(opts...)
	reasons := LaunchOptionReasons(buildDir)

	targetsMemo := map[string][]string{}
	targets := func(coord string) []string {
		if t, ok := targetsMemo[coord]; ok {
			return t
		}
		var t []string
		if g != nil {
			t = BlindSpotTargets(g, coord)
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
	if g == nil {
		cp.Unlisted = true
		reasons = append([]string{PartialReasonBuildGraphAbsent}, reasons...)
	} else {
		cp.JDK = g.RuntimeJDK()
		if OtherToolBuild(g, buildDir) {
			reasons = append([]string{PartialReasonOtherToolBuild}, reasons...)
		}
		load, miss := RuntimeSelection(g)
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

	closureCache.Lock()
	hit, ok := closureCache.m[buildDir]
	closureCache.Unlock()
	if ok && hit.key == fingerprint {
		out := *hit.rc
		out.Scoped = append(rc.Scoped, hit.rc.Scoped...)
		out.Reasons = append(reasons, hit.rc.releaseReasons...)
		return &out, nil
	}

	isFirstParty := make(map[string]bool, len(firstParty))
	for _, c := range firstParty {
		isFirstParty[c.Name] = true
	}
	built := &reachClosure{Loaded: map[string]string{}}
	definedBy := map[string]gav{}
	shadowReported := map[string]bool{}
	all := append([]classfile.Class{}, firstParty...)
	versioned := make([][]classfile.VersionedClass, len(jars))
	for ji, j := range jars {
		jr, err := loadJarCached(j.jar)
		if err != nil {
			built.Scoped = append(built.Scoped, scoped(plugin.PartialReasonToolFailure, j.gav.coordinate, j.gav.String()+": "+err.Error()))
			continue
		}
		if len(jr.Failed) > 0 {
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
	built.index(all)

	closureCache.Lock()
	closureCache.m[buildDir] = closureEntry{key: fingerprint, rc: built}
	closureCache.Unlock()

	out := *built
	out.Scoped = append(rc.Scoped, built.Scoped...)
	out.Reasons = append(reasons, built.releaseReasons...)
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

// firstPartyFingerprint digests what the engine reads from the first-party classes: each
// class's hierarchy, and each method's flags and call edges.
func firstPartyFingerprint(classes []classfile.Class) string {
	lines := make([]string, 0, len(classes))
	for _, c := range classes {
		var b strings.Builder
		fmt.Fprintf(&b, "%s<%s%v", c.Name, c.Super, c.Interfaces)
		for _, m := range c.Methods {
			fmt.Fprintf(&b, "|%s:%v%v", m.Ref, m.Abstract, m.Native)
			for _, e := range m.Edges {
				fmt.Fprintf(&b, ",%v", e)
			}
			for _, e := range m.InitTriggers {
				fmt.Fprintf(&b, ";%v", e)
			}
		}
		lines = append(lines, b.String())
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:])
}

// concrete reports whether the closure holds a body for ref: declared in loaded code and
// neither abstract nor native. Only such a sink can be cleared by an empty search; an
// abstract or native one stands for code the search did not walk.
func (rc *reachClosure) concrete(ref classfile.MethodRef) bool {
	m, ok := rc.methods[ref.String()]
	return ok && !m.Abstract && !m.Native
}

// index records the classes and methods of all that run, as the engine does: a classpath copy
// of a class the JVM loads only from the JDK is left out.
func (rc *reachClosure) index(all []classfile.Class) {
	rc.methods = make(map[string]classfile.Method)
	rc.classes = make(map[string]*classfile.Class, len(all))
	for i := range all {
		if depreach.BootOnly(all[i].Name) {
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
