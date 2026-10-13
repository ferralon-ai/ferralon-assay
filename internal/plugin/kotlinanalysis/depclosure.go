package kotlinanalysis

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depclosure.go — load the build's resolved dependency closure so Reachability traces from
// first-party code into the exact dependency bytecode the build resolved. The node set comes
// from the shared JVM inventory (javaanalysis.ResolveInventory: Maven reactor + .m2 POMs, or
// the Gradle lockfile + modules-2 POMs, or Gradle declared-direct without a lockfile); each
// node's JAR is located in the local caches by LocateDependencyJar (Gradle modules-2, then
// .m2) and parsed by the shared classfile reader.
//
// With a Gradle lockfile, a locked coordinate loads only the version runtimeClasspath locks
// (gradlelocks.go), the one the application runs with: a coordinate locked only for kapt, an
// annotation processor or a test classpath is not loaded, and one locked at more than one
// runtime version, or at a version that is not concrete, is a scoped blind spot rather than a
// guess.
//
// A dependency that is in the inventory but whose JAR cannot be opened is a blind spot bounded
// by what it could reach (contract §4): a ScopedReason whose Targets are the JAR's package, its
// transitive dependency closure, first-party code ("") and first-party code's own dependency
// closure. The unseen code can hold first-party objects and call back into them through any type
// it knows, or load first-party classes reflectively, and first-party code reaches whatever it
// depends on. Targets is nil (unbounded) when either closure is not fully known: a node in it
// carries a relationship_unexpressed reason, so its out-edges were never read, or the inventory
// itself is partial.
//
// When the build has Gradle start scripts (runtimeclasspath.go), their classpath replaces the
// inventory: it lists every JAR the JVM is launched with, transitive ones included, in launch
// order. A classpath JAR that cannot be found or read has no known closure, so its scoped
// reason is unbounded.
//
// A dependency the inventory does not list at all is never silently trusted: depreach treats
// any call into a class that is neither loaded nor platform as an unloaded_dependency hazard,
// so reaching it makes the search undetermined.

// partialReasonMissingJar is the scoped reason for an inventory node whose JAR is not in any
// local cache (or whose version is unresolved, so no JAR can be located). Same string as
// javaanalysis's maven_uncached_subtree: its subtree's code is unseen.
const partialReasonMissingJar = plugin.PartialReasonRelationshipUnexpressed + ":maven_uncached_subtree"

// partialReasonDuplicateClass is the scoped reason for a dependency class whose binary name a
// previously loaded JAR already defined. The engine keeps one body per name, so the shadowed
// body's edges are unseen.
const partialReasonDuplicateClass = plugin.PartialReasonRelationshipUnexpressed + ":duplicate_class"

// partialReasonRuntimeVersionAmbiguous is the scoped reason for a dependency whose runtime
// version cannot be selected: the Gradle lockfile locks it in runtimeClasspath at more than one
// version, or at one that is not concrete.
// Loading any one candidate could trace bytes that never run, so none is loaded.
const partialReasonRuntimeVersionAmbiguous = plugin.PartialReasonRelationshipUnexpressed + ":runtime_version_ambiguous"

// depClosure is the loaded dependency bytecode plus the scoped blind spots loading it incurred.
type depClosure struct {
	classes []classfile.Class
	scoped  []plugin.ScopedReason
	// loaded maps "group:artifact:version" (or the classpath JAR name) to the JAR path that
	// was opened, for evidence.
	loaded map[string]string
	// mainClasses are the launch main classes the start scripts name; empty when the
	// closure came from the inventory.
	mainClasses []string
}

// depNode is one distinct (group, artifact, version) from the inventory, with the inventory
// node IDs that carry it.
type depNode struct {
	group, artifact, version string
	ids                      []string
}

func (n depNode) coordinate() string { return n.group + ":" + n.artifact }
func (n depNode) packageURL() string { return "pkg:maven/" + n.group + "/" + n.artifact }
func (n depNode) gav() string        { return n.coordinate() + ":" + n.version }

// loadDependencyClosure resolves the inventory for buildDir and loads every node's JAR it can
// locate. firstParty names classes already loaded from the build output; a dependency class
// with the same binary name is skipped (the build output is what the build packaged).
func loadDependencyClosure(ctx context.Context, buildDir string, firstParty map[string]bool) (*depClosure, error) {
	if rc, ok := findRuntimeClasspath(buildDir); ok {
		return loadRuntimeClasspath(buildDir, rc, firstParty), nil
	}
	inv, err := javaanalysis.ResolveInventory(ctx, plugin.ResolveInventoryRequest{BuildDir: buildDir})
	if err != nil {
		return nil, err
	}
	g := newInventoryGraph(inv)
	program := g.programClosure()
	targets := func(n depNode) []string { return blindSpotTargets(g.targets(n), program) }
	dc := &depClosure{loaded: map[string]string{}}

	var locks *runtimeLocks
	if fromLockfile(inv) {
		if rl, ok := readRuntimeLocks(buildDir); ok {
			locks = &rl
		}
	}
	load, misses := g.runtimeSelection(locks)
	for _, m := range misses {
		dc.scoped = append(dc.scoped, plugin.ScopedReason{
			Reason:  partialReasonRuntimeVersionAmbiguous,
			Package: m.node.packageURL(),
			Path:    m.detail,
			Targets: targets(m.node),
		})
	}

	definedBy := map[string]depNode{} // class binary name -> the dependency that defined it
	shadowed := map[string]bool{}     // "<kept gav>|<shadowed gav>" pairs already reported

	for _, n := range load {
		jarPath, ok := "", false
		if n.version != "" {
			jarPath, ok = LocateDependencyJar(buildDir, n.coordinate(), n.version)
		}
		if !ok {
			dc.scoped = append(dc.scoped, plugin.ScopedReason{
				Reason:  partialReasonMissingJar,
				Package: n.packageURL(),
				Path:    n.gav(),
				Targets: targets(n),
			})
			continue
		}
		jr, err := classfile.LoadJar(jarPath)
		if err != nil {
			dc.scoped = append(dc.scoped, plugin.ScopedReason{
				Reason:  plugin.PartialReasonToolFailure,
				Package: n.packageURL(),
				Path:    n.gav(),
				Targets: targets(n),
			})
			continue
		}
		if len(jr.Failed) > 0 {
			// Unparsed classes are absent from the engine, so a call into one is already an
			// unloaded_dependency hazard; the scoped reason discloses the gap and bounds it.
			dc.scoped = append(dc.scoped, plugin.ScopedReason{
				Reason:  plugin.PartialReasonToolFailure,
				Package: n.packageURL(),
				Path:    n.gav() + ": " + jr.Failed[0],
				Targets: targets(n),
			})
		}
		dc.loaded[n.gav()] = jarPath
		for _, c := range jr.Classes {
			if firstParty[c.Name] {
				continue
			}
			if prev, dup := definedBy[c.Name]; dup {
				key := prev.gav() + "|" + n.gav()
				if !shadowed[key] {
					shadowed[key] = true
					dc.scoped = append(dc.scoped, plugin.ScopedReason{
						Reason:  partialReasonDuplicateClass,
						Package: n.packageURL(),
						Path:    fmt.Sprintf("%s shadowed by %s: %s", n.gav(), prev.gav(), c.Name),
						Targets: targets(n),
					})
				}
				continue
			}
			definedBy[c.Name] = n
			dc.classes = append(dc.classes, c)
		}
	}
	return dc, nil
}

// loadRuntimeClasspath loads the start-script classpath. On an ordered classpath a class
// already defined by an earlier JAR (or by first-party output) is skipped silently: the JVM
// loads the first definition, so the later copy never runs. On an unordered union of
// differing classpaths that is unknown, and the duplicate is a scoped reason.
func loadRuntimeClasspath(buildDir string, rc runtimeClasspath, firstParty map[string]bool) *depClosure {
	index := gradleCacheIndex(buildDir)
	dc := &depClosure{loaded: map[string]string{}, mainClasses: rc.mainClasses}
	definedBy := map[string]string{}
	shadowed := map[string]bool{}
	for _, name := range rc.entries {
		jar, ok := locateClasspathJar(buildDir, rc, index, name)
		if !ok {
			dc.scoped = append(dc.scoped, plugin.ScopedReason{Reason: partialReasonMissingJar, Package: cacheOnlyPackage(index[name]), Path: "classpath: " + name})
			continue
		}
		pkg := jar.packageURL()
		jr, err := classfile.LoadJar(jar.path)
		if err != nil {
			dc.scoped = append(dc.scoped, plugin.ScopedReason{Reason: plugin.PartialReasonToolFailure, Package: pkg, Path: "classpath: " + name})
			continue
		}
		if len(jr.Failed) > 0 {
			dc.scoped = append(dc.scoped, plugin.ScopedReason{Reason: plugin.PartialReasonToolFailure, Package: pkg, Path: "classpath: " + name + ": " + jr.Failed[0]})
		}
		dc.loaded[name] = jar.path
		for _, c := range jr.Classes {
			if firstParty[c.Name] {
				continue
			}
			if prev, dup := definedBy[c.Name]; dup {
				if !rc.ordered && !shadowed[prev+"|"+name] {
					shadowed[prev+"|"+name] = true
					dc.scoped = append(dc.scoped, plugin.ScopedReason{
						Reason:  partialReasonDuplicateClass,
						Package: pkg,
						Path:    fmt.Sprintf("classpath: %s shadowed by %s: %s", name, prev, c.Name),
					})
				}
				continue
			}
			definedBy[c.Name] = name
			dc.classes = append(dc.classes, c)
		}
	}
	return dc
}

// cacheOnlyPackage names the package of a classpath JAR that could not be used, when the
// cache paths agree on one ("" otherwise).
func cacheOnlyPackage(paths []string) string {
	if g, a, _ := cacheCoordinate(paths); g != "" {
		return "pkg:maven/" + g + "/" + a
	}
	return ""
}

// blindSpotTargets is the §4 bound for an unloaded dependency: its own closure plus first-party
// code ("") and first-party code's dependency closure. nil when either closure is unknown.
func blindSpotTargets(own, program []string) []string {
	if own == nil || program == nil {
		return nil
	}
	set := map[string]bool{"": true}
	for _, p := range own {
		set[p] = true
	}
	for _, p := range program {
		set[p] = true
	}
	return sortedKeys(set)
}

// inventoryGraph indexes a DependencyInventory for closure queries.
type inventoryGraph struct {
	byID     map[string]plugin.DependencyNode
	children map[string][]string
	nodes    []depNode
	// complete is false when the inventory declared graph-level partiality: packages it could
	// not name may be on the classpath.
	complete bool
}

func newInventoryGraph(inv plugin.DependencyInventory) *inventoryGraph {
	g := &inventoryGraph{
		byID:     map[string]plugin.DependencyNode{},
		children: map[string][]string{},
		complete: len(inv.Partiality.Reasons) == 0 && len(inv.Partiality.Scoped) == 0,
	}
	byGAV := map[string]*depNode{}
	var order []string
	for _, n := range inv.Nodes {
		g.byID[n.ID] = n
		group, artifact, version, ok := splitMavenNodePURL(n.PURL)
		if !ok {
			continue
		}
		if version == "" {
			version = n.Version
		}
		key := group + ":" + artifact + ":" + version
		if d, seen := byGAV[key]; seen {
			d.ids = append(d.ids, n.ID)
			continue
		}
		byGAV[key] = &depNode{group: group, artifact: artifact, version: version, ids: []string{n.ID}}
		order = append(order, key)
	}
	for _, e := range inv.Edges {
		g.children[e.Parent] = append(g.children[e.Parent], e.Child)
	}
	sort.Strings(order)
	for _, k := range order {
		g.nodes = append(g.nodes, *byGAV[k])
	}
	return g
}

// versionMiss is a dependency whose runtime version could not be selected: node carries every
// inventory node ID of the group:artifact and no version; detail names what the lockfile locks.
type versionMiss struct {
	node   depNode
	detail string
}

// runtimeSelection returns the dependencies whose JARs the closure loads, in inventory order.
// Without a lockfile (locks nil) that is every inventory node. With one, a locked coordinate
// loads the single concrete version runtimeClasspath locks, whichever version the inventory node
// names; one locked only in other configurations (kapt, annotationProcessor, ksp, test) is not on
// the runtime classpath and is not loaded, so a call into it stays an unloaded_dependency hazard;
// one runtimeClasspath locks at more than one version, or at one that is not concrete, is a miss
// and loads nothing. A coordinate the lockfile does not lock loads the inventory's version.
func (g *inventoryGraph) runtimeSelection(locks *runtimeLocks) (load []depNode, misses []versionMiss) {
	if locks == nil {
		return g.nodes, nil
	}
	merged := map[string]*depNode{}
	var locked []string
	for _, n := range g.nodes {
		c := n.coordinate()
		if !locks.locked[c] {
			load = append(load, n)
			continue
		}
		if m, ok := merged[c]; ok {
			m.ids = append(m.ids, n.ids...)
			continue
		}
		merged[c] = &depNode{group: n.group, artifact: n.artifact, ids: append([]string(nil), n.ids...)}
		locked = append(locked, c)
	}
	sort.Strings(locked)
	for _, c := range locked {
		m := *merged[c]
		version, detail, onRuntime := locks.selection(c)
		switch {
		case !onRuntime:
		case version == "":
			misses = append(misses, versionMiss{node: m, detail: detail})
		default:
			m.version = version
			load = append(load, m)
		}
	}
	return load, misses
}

// fromLockfile reports whether the inventory's node set came from a Gradle lockfile.
func fromLockfile(inv plugin.DependencyInventory) bool {
	for _, n := range inv.Nodes {
		if n.Provenance.Resolver == "gradle-lockfile" {
			return true
		}
	}
	return false
}

// targets returns the packages (PURL without version) any code in n could reach: n itself and
// its transitive dependency closure. It is nil (unbounded) when some node in that closure has
// out-edges the inventory could not read (a relationship_unexpressed reason on the node) or a
// node is not a Maven package.
func (g *inventoryGraph) targets(n depNode) []string {
	seen := map[string]bool{}
	out := map[string]bool{}
	stack := append([]string(nil), n.ids...)
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		node, ok := g.byID[id]
		if !ok {
			return nil
		}
		for _, r := range node.Partiality.Reasons {
			if strings.HasPrefix(r, plugin.PartialReasonRelationshipUnexpressed) {
				return nil
			}
		}
		group, artifact, _, ok := splitMavenNodePURL(node.PURL)
		if !ok {
			return nil
		}
		out["pkg:maven/"+group+"/"+artifact] = true
		stack = append(stack, g.children[id]...)
	}
	return sortedKeys(out)
}

// programClosure returns the packages first-party code could reach: the dependency closure of the
// whole program, taken as every node in the inventory. nil when that is not fully known.
func (g *inventoryGraph) programClosure() []string {
	if !g.complete {
		return nil
	}
	for _, n := range g.byID {
		// A node newInventoryGraph skipped (not a Maven package) has an unknown closure.
		if _, _, _, ok := splitMavenNodePURL(n.PURL); !ok {
			return nil
		}
	}
	out := map[string]bool{}
	for _, n := range g.nodes {
		ts := g.targets(n)
		if ts == nil {
			return nil
		}
		for _, t := range ts {
			out[t] = true
		}
	}
	return sortedKeys(out)
}

// splitMavenNodePURL parses an inventory node PURL "pkg:maven/<group>/<artifact>@<version>".
func splitMavenNodePURL(purl string) (group, artifact, version string, ok bool) {
	coordinate, version, ok := parseMavenPURL(purl)
	if !ok {
		return "", "", "", false
	}
	group, artifact, ok = splitCoordinate(coordinate)
	return group, artifact, version, ok
}
