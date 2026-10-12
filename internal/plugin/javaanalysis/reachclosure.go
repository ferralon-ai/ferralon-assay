package javaanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reachclosure.go — the whole-program classpath a bytecode reachability search runs over:
// the build's compiled classes plus every dependency JAR the inventory resolved
// (ResolveInventory: the effective graph, transitive nodes included). JARs are located in
// the local caches, never fetched.
//
// Every blind spot is a ScopedReason bounded by what the unseen code could call
// (unloadedJarTargets; nil when that closure cannot be bounded):
//   - a node with no resolved version, whose JAR no cache holds, or that the build declares
//     with a classifier or non-jar type → tool_failure:no_dependency_artifact;
//   - a JAR that cannot be opened, or classes in it that fail to parse → tool_failure;
//   - a class two JARs define → relationship_unexpressed:duplicate_class (the engine keeps
//     one body per binary name, so the other body's calls are unseen).
//
// A call into a class that is neither loaded nor a JDK platform class is an
// unloaded_dependency hazard inside depreach, so code the inventory never listed is never
// silently trusted.
//
// This mirrors kotlinanalysis's dependency closure rather than sharing a package with it:
// the two lanes read first-party code differently (Java from source plus compiled output,
// Kotlin from bytecode only), and the shared part is the loop below.

const reasonDuplicateClass = plugin.PartialReasonRelationshipUnexpressed + ":duplicate_class"

// reachClosure is the engine over first-party plus dependency bytecode and the scoped blind
// spots loading the dependencies incurred.
type reachClosure struct {
	Engine *depreach.Engine
	Scoped []plugin.ScopedReason
	// methods indexes every loaded method by depreach's MethodRef.String() key, for the
	// sink-concreteness check.
	methods map[string]classfile.Method
	// Loaded maps "group:artifact:version" to the JAR that was opened, for evidence.
	Loaded map[string]string
}

// gav is one distinct (coordinate, version) from the inventory.
type gav struct{ coordinate, version string }

func (g gav) String() string { return g.coordinate + ":" + g.version }

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

// loadReachClosure resolves the inventory for buildDir and loads every node's JAR it can
// locate. firstParty is the build's compiled output: it goes into the engine, and a
// dependency class with the same binary name is skipped, since the build output is what
// the build packaged.
func loadReachClosure(ctx context.Context, buildDir string, firstParty []classfile.Class) (*reachClosure, error) {
	inv, err := ResolveInventory(ctx, plugin.ResolveInventoryRequest{BuildDir: buildDir})
	if err != nil {
		return nil, err
	}
	ix := indexInventory(inv)
	cache := newMavenCache(buildDir)
	reactor := reactorCoordinates(buildDir)

	targetsMemo := map[string][]string{}
	targets := func(coord string) []string {
		if t, ok := targetsMemo[coord]; ok {
			return t
		}
		t := unloadedJarTargets(ix, cache, coord)
		targetsMemo[coord] = t
		return t
	}
	scoped := func(reason, coord, path string) plugin.ScopedReason {
		return plugin.ScopedReason{Reason: reason, Package: mavenPURLNoVersion(coord), Path: path, Targets: targets(coord)}
	}

	rc := &reachClosure{Loaded: map[string]string{}}
	type opened struct {
		gav gav
		jar string
	}
	var jars []opened
	fp := sha256.New()
	for _, n := range distinctGAVs(ix, reactor) {
		switch {
		case n.version == "":
			rc.Scoped = append(rc.Scoped, scoped(reasonNoDependencyArtifact, n.coordinate, n.coordinate))
			continue
		case ix.variantAt(n.coordinate, n.version):
			rc.Scoped = append(rc.Scoped, scoped(reasonNoDependencyArtifact, n.coordinate, n.String()+": artifact variant declared"))
			continue
		}
		jarPath, ok, ambiguous := locateArtifactJar(buildDir, n.coordinate, n.version)
		switch {
		case ambiguous:
			rc.Scoped = append(rc.Scoped, scoped(reasonNoDependencyArtifact, n.coordinate, n.String()+": cached copies differ"))
			continue
		case !ok:
			rc.Scoped = append(rc.Scoped, scoped(reasonNoDependencyArtifact, n.coordinate, n.String()))
			continue
		}
		key, err := jarKey(jarPath)
		if err != nil {
			rc.Scoped = append(rc.Scoped, scoped(plugin.PartialReasonToolFailure, n.coordinate, n.String()+": "+err.Error()))
			continue
		}
		fmt.Fprintln(fp, key)
		jars = append(jars, opened{n, jarPath})
	}
	fmt.Fprintln(fp, firstPartyFingerprint(firstParty))
	fingerprint := hex.EncodeToString(fp.Sum(nil))

	closureCache.Lock()
	hit, ok := closureCache.m[buildDir]
	closureCache.Unlock()
	if ok && hit.key == fingerprint {
		out := *hit.rc
		out.Scoped = append(rc.Scoped, hit.rc.Scoped...)
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
	for _, j := range jars {
		jr, err := loadJarCached(j.jar)
		if err != nil {
			built.Scoped = append(built.Scoped, scoped(plugin.PartialReasonToolFailure, j.gav.coordinate, j.gav.String()+": "+err.Error()))
			continue
		}
		if len(jr.Failed) > 0 {
			built.Scoped = append(built.Scoped, scoped(plugin.PartialReasonToolFailure, j.gav.coordinate, j.gav.String()+"!"+strings.SplitN(jr.Failed[0], ": ", 2)[0]))
		}
		built.Loaded[j.gav.String()] = j.jar
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
	built.Engine = depreach.NewEngine(all)
	built.methods = make(map[string]classfile.Method)
	for _, c := range all {
		for _, m := range c.Methods {
			built.methods[m.Ref.String()] = m
		}
	}

	closureCache.Lock()
	closureCache.m[buildDir] = closureEntry{key: fingerprint, rc: built}
	closureCache.Unlock()

	out := *built
	out.Scoped = append(rc.Scoped, built.Scoped...)
	return &out, nil
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

// distinctGAVs returns one entry per distinct (coordinate, version) the inventory holds,
// sorted so the load order (and so which JAR wins a duplicate class) is deterministic. The
// build's own reactor modules are left out: their code is the first-party build output.
func distinctGAVs(ix inventoryIndex, reactor map[string]bool) []gav {
	seen := map[gav]bool{}
	var out []gav
	for coord, nodes := range ix.byCoordinate {
		if reactor[coord] {
			continue
		}
		for _, n := range nodes {
			g := gav{coordinate: coord, version: n.Version}
			if !seen[g] {
				seen[g] = true
				out = append(out, g)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].coordinate != out[j].coordinate {
			return out[i].coordinate < out[j].coordinate
		}
		return out[i].version < out[j].version
	})
	return out
}

// reactorCoordinates returns the "group:artifact" of every Maven module under buildDir.
func reactorCoordinates(buildDir string) map[string]bool {
	out := map[string]bool{}
	for _, p := range findPOMs(buildDir) {
		pom, ok := parseMavenPOM(p)
		if !ok || pom.ArtifactID == "" {
			continue
		}
		out[pom.GroupID+":"+pom.ArtifactID] = true
	}
	return out
}

// jarCache keeps each parsed JAR for the life of the plugin process, keyed by path, size
// and modification time, so a rewritten JAR is re-read.
var jarCache = struct {
	sync.Mutex
	m map[string]classfile.JarResult
}{m: map[string]classfile.JarResult{}}

func jarKey(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s\x00%d\x00%d", filepath.Clean(path), info.Size(), info.ModTime().UnixNano()), nil
}

func loadJarCached(path string) (classfile.JarResult, error) {
	key, err := jarKey(path)
	if err != nil {
		return classfile.JarResult{}, err
	}
	jarCache.Lock()
	jr, ok := jarCache.m[key]
	jarCache.Unlock()
	if ok {
		return jr, nil
	}
	jr, err = classfile.LoadJar(path)
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
